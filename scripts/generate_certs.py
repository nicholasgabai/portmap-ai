#!/usr/bin/env python3
"""Generate self-signed certificates for PortMap-AI development."""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path

DEFAULT_CA_SUBJECT = "/CN=PortMap-AI Dev CA"
DEFAULT_MASTER_SUBJECT = "/CN=portmap-master"
DEFAULT_WORKER_SUBJECT = "/CN=portmap-worker"


def run(cmd):
    subprocess.run(cmd, check=True)


def generate_certs(output_dir: Path, ca_subject: str, master_subject: str, worker_subject: str) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)

    ca_key = output_dir / "ca.key"
    ca_cert = output_dir / "ca.crt"
    master_key = output_dir / "master.key"
    master_csr = output_dir / "master.csr"
    master_cert = output_dir / "master.crt"
    worker_key = output_dir / "worker.key"
    worker_csr = output_dir / "worker.csr"
    worker_cert = output_dir / "worker.crt"

    # CA
    run([
        "openssl",
        "req",
        "-x509",
        "-nodes",
        "-newkey",
        "rsa:4096",
        "-sha256",
        "-days",
        "825",
        "-keyout",
        str(ca_key),
        "-out",
        str(ca_cert),
        "-subj",
        ca_subject,
    ])

    # Master cert
    run([
        "openssl",
        "req",
        "-nodes",
        "-newkey",
        "rsa:4096",
        "-keyout",
        str(master_key),
        "-out",
        str(master_csr),
        "-subj",
        master_subject,
    ])
    run([
        "openssl",
        "x509",
        "-req",
        "-in",
        str(master_csr),
        "-CA",
        str(ca_cert),
        "-CAkey",
        str(ca_key),
        "-CAcreateserial",
        "-out",
        str(master_cert),
        "-days",
        "825",
        "-sha256",
    ])

    # Worker cert
    run([
        "openssl",
        "req",
        "-nodes",
        "-newkey",
        "rsa:4096",
        "-keyout",
        str(worker_key),
        "-out",
        str(worker_csr),
        "-subj",
        worker_subject,
    ])
    run([
        "openssl",
        "x509",
        "-req",
        "-in",
        str(worker_csr),
        "-CA",
        str(ca_cert),
        "-CAkey",
        str(ca_key),
        "-CAcreateserial",
        "-out",
        str(worker_cert),
        "-days",
        "825",
        "-sha256",
    ])

    print(f"Certificates written to {output_dir}")


def main():
    parser = argparse.ArgumentParser(description="Generate self-signed certs for PortMap-AI")
    parser.add_argument("--output-dir", default=str(Path.home() / ".portmap-ai" / "certs"))
    parser.add_argument("--ca-subject", default=DEFAULT_CA_SUBJECT)
    parser.add_argument("--master-subject", default=DEFAULT_MASTER_SUBJECT)
    parser.add_argument("--worker-subject", default=DEFAULT_WORKER_SUBJECT)
    args = parser.parse_args()

    generate_certs(Path(args.output_dir), args.ca_subject, args.master_subject, args.worker_subject)


if __name__ == "__main__":
    main()
