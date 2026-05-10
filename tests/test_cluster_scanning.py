import json

import pytest

from core_engine.cluster.job_queue import JobQueue
from core_engine.cluster.scheduler import plan_distributed_scan
from core_engine.cluster.worker_registry import WorkerRegistry, worker_from_dict, workers_from_orchestrator_nodes


def test_worker_registry_filters_available_workers():
    registry = WorkerRegistry(
        [
            {"node_id": "worker-a", "status": "ready", "meta": {"max_concurrency": 2}},
            {"node_id": "worker-b", "status": "offline"},
            {"node_id": "worker-c", "status": "ready", "capabilities": {"scan_types": ["udp"]}},
        ],
        stale_after_seconds=0,
    )

    workers = registry.available_workers(scan_type="tcp_connect")

    assert [worker.node_id for worker in workers] == ["worker-a"]
    assert workers[0].available_capacity == 2


def test_workers_from_orchestrator_nodes_uses_worker_role_only():
    workers = workers_from_orchestrator_nodes(
        [
            {"node_id": "master-1", "role": "master", "status": "ready"},
            {"node_id": "worker-1", "role": "worker", "status": "ready"},
        ]
    )

    assert [worker.node_id for worker in workers] == ["worker-1"]


def test_plan_distributed_scan_balances_tasks_without_running_scan():
    payload = plan_distributed_scan(
        "127.0.0.1",
        [80, 443, 8080],
        workers=[
            {"node_id": "worker-a", "status": "ready", "max_concurrency": 1},
            {"node_id": "worker-b", "status": "ready", "max_concurrency": 1},
        ],
        target_chunk_size=1,
        port_chunk_size=1,
    )

    assert payload["ok"] is True
    assert payload["mode"] == "dry_run"
    assert payload["automatic_changes"] is False
    assert payload["raw_payload_stored"] is False
    assert payload["summary"]["task_count"] == 3
    assert payload["summary"]["assigned_tasks"] == 3
    assert {item["worker_id"] for item in payload["assignments"]} == {"worker-a", "worker-b"}
    assert payload["job"]["status"] == "planned"
    assert all(task["assigned_worker"] for task in payload["job"]["tasks"])
    assert all(task["attempts"] == 0 for task in payload["job"]["tasks"])
    assert all(task["status"] == "planned" for task in payload["job"]["tasks"])


def test_plan_distributed_scan_keeps_tasks_queued_without_available_workers():
    payload = plan_distributed_scan(
        "127.0.0.1",
        [443],
        workers=[{"node_id": "worker-a", "status": "offline"}],
    )

    assert payload["summary"]["available_workers"] == 0
    assert payload["summary"]["queued_tasks"] == 1
    assert payload["assignments"] == []
    assert "no available workers" in payload["warnings"][0]


def test_job_queue_retries_and_aggregates_partial_results():
    payload = plan_distributed_scan("127.0.0.1", [80], workers=[{"node_id": "worker-a", "status": "ready"}])
    job_data = payload["job"]
    task_data = job_data["tasks"][0]
    task = worker_from_dict({"node_id": "worker-a"})
    assert task.node_id == "worker-a"

    from core_engine.cluster.job_queue import ClusterJob, ClusterTask

    job = ClusterJob(
        job_id=job_data["job_id"],
        tasks=[
            ClusterTask(
                task_id=task_data["task_id"],
                job_id=job_data["job_id"],
                targets=task_data["targets"],
                ports=task_data["ports"],
                assigned_worker="worker-a",
                attempts=1,
                max_retries=0,
                status="assigned",
            )
        ],
    )
    queue = JobQueue([job])
    queue.record_result(task_data["task_id"], success=True, result={"rows": [{"target": "127.0.0.1", "port": 80}]})
    aggregate = queue.aggregate_results(job.job_id)

    assert aggregate["ok"] is True
    assert aggregate["status"] == "completed"
    assert aggregate["result_count"] == 1
    assert aggregate["results"][0]["port"] == 80


def test_plan_rejects_invalid_chunk_size():
    with pytest.raises(ValueError, match="target_chunk_size"):
        plan_distributed_scan("127.0.0.1", [80], target_chunk_size=0)


def test_cluster_payload_is_json_serializable():
    payload = plan_distributed_scan("127.0.0.1", [80], workers=[{"node_id": "worker-a", "status": "ready"}])

    assert json.loads(json.dumps(payload))["summary"]["total_probes"] == 1
