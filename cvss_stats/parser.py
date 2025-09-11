def load_file(path):
    """Load input file and return a list of CVSS vector strings."""
    with open(path, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]
    return lines
