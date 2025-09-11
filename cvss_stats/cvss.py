# cvss_stats/cvss.py

def calculate_score(vector_dict):
    """
    Placeholder for CVSS 3.1 score calculation.
    For now, just return a fake score (e.g., 5.0) or something simple.
    Later we'll implement the full math.
    """
    # TODO: implement real CVSS 3.1 base score calculation
    return 5.0


def classify_severity(score):
    """Classify a numeric CVSS score into severity levels."""
    if score == 0.0:
        return "None"
    elif 0.1 <= score <= 3.9:
        return "Low"
    elif 4.0 <= score <= 6.9:
        return "Medium"
    elif 7.0 <= score <= 8.9:
        return "High"
    elif 9.0 <= score <= 10.0:
        return "Critical"
    else:
        return "Unknown"
