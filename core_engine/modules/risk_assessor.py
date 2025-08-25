# risk_assessor.py

from ai_agent.ml_data_logger import log_connection
from ai_agent.scoring import get_score
from behavior_profiler import detect_behavioral_anomaly


def calculate_risk_score(connection, logger=None, autolearn=False):
    detect_behavioral_anomaly(connection, autolearn=autolearn)  # modifies in-place

    if logger:
        logger.debug(f"🔬 Behavior flag: {connection.get('behavior_flag')} for {connection['program']} on port {connection['port']}")

    score = get_score(connection)
    connection["score"] = score

    if logger:
        logger.debug(f"📊 Risk score for {connection['program']} on port {connection['port']}: {score}")

    log_connection(connection)
    return connection

