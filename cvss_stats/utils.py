SEVERITY_THRESHOLDS = {
    "Low": (0.1, 3.9),
    "Medium": (4.0, 6.9),
    "High": (7.0, 8.9),
    "Critical": (9.0, 10.0)
}

# Metric numerical values (from CVSS 3.1 spec)
METRIC_VALUES = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {
        "N": {"U": 0.85, "C": 0.85},  # Privileges Required None
        "L": {"U": 0.62, "C": 0.68},
        "H": {"U": 0.27, "C": 0.5}
    },
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"N": 0.0, "L": 0.22, "H": 0.56},
    "I": {"N": 0.0, "L": 0.22, "H": 0.56},
    "A": {"N": 0.0, "L": 0.22, "H": 0.56},
}
