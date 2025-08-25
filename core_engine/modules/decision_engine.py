from ai_agent.scoring import get_score

def score_connection(connection, enable_ml=False):
    return get_score(connection, enable_ml)

def make_decision(connection, logger=None, enable_ml=False):
    score = score_connection(connection, enable_ml)
    connection["score"] = score
    if logger and logger.level == 10:
        print(f"📊 Risk score for {connection['program']} on port {connection['port']}: {score}")
    if score > 0.8:
        return "block"
    elif score > 0.5:
        return "review"
    return "allow"

