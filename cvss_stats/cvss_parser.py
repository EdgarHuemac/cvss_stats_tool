import re

VALID_METRICS = {
    "AV": ["N", "A", "L", "P"],       # Attack Vector
    "AC": ["L", "H"],                 # Attack Complexity
    "PR": ["N", "L", "H"],            # Privileges Required
    "UI": ["N", "R"],                 # User Interaction
    "S":  ["U", "C"],                 # Scope
    "C":  ["N", "L", "H"],            # Confidentiality Impact
    "I":  ["N", "L", "H"],            # Integrity Impact
    "A":  ["N", "L", "H"]             # Availability Impact
}

def parse_vector(vector_str, version="3.1"):
    """
    Parse a single CVSS vector string into a structured dictionary.
    Example input: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    """
    if not vector_str.startswith(f"CVSS:{version}"):
        raise ValueError(f"Invalid CVSS vector (expected version {version}): {vector_str}")

    # Split into parts after the "CVSS:3.1"
    parts = vector_str.split("/")[1:]  # drop "CVSS:3.1"
    
    metrics = {}
    for part in parts:
        if ":" not in part:
            continue
        key, value = part.split(":")
        if key not in VALID_METRICS:
            raise ValueError(f"Unknown metric '{key}' in vector: {vector_str}")
        if value not in VALID_METRICS[key]:
            raise ValueError(f"Invalid value '{value}' for metric '{key}' in vector: {vector_str}")
        metrics[key] = value

    return {
        "version": version,
        "raw": vector_str,
        "metrics": metrics
    }

def parse_vectors(vectors, version="3.1"):
    """
    Parse a list of CVSS vectors into structured dictionaries.
    """
    parsed = []
    for v in vectors:
        try:
            parsed.append(parse_vector(v, version=version))
        except ValueError as e:
            # Skip or log invalid vectors for now
            print(f"[!] Skipping invalid vector: {v} ({e})")
    return parsed
