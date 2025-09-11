from cvss_stats.utils import METRIC_VALUES, SEVERITY_THRESHOLDS
import math
from collections import Counter, defaultdict, OrderedDict

def round_up(x):
    return math.ceil(x * 10) / 10.0

def calculate_score(metrics):
    av = METRIC_VALUES["AV"][metrics["AV"]]
    ac = METRIC_VALUES["AC"][metrics["AC"]]
    pr = METRIC_VALUES["PR"][metrics["PR"]][metrics["S"]]  # depends on scope
    ui = METRIC_VALUES["UI"][metrics["UI"]]
    c = METRIC_VALUES["C"][metrics["C"]]
    i = METRIC_VALUES["I"][metrics["I"]]
    a = METRIC_VALUES["A"][metrics["A"]]
    scope = metrics["S"]

    exploitability = 8.22 * av * ac * pr * ui
    isc_base = 1 - ((1 - c) * (1 - i) * (1 - a))

    if scope == "U":
        impact = 6.42 * isc_base
    else:
        impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15

    if impact <= 0:
        return 0.0

    if scope == "U":
        score = round_up(min(impact + exploitability, 10))
    else:
        score = round_up(min(1.08 * (impact + exploitability), 10))

    return score

def classify_severity(score):
    for sev, (low, high) in SEVERITY_THRESHOLDS.items():
        if low <= score <= high:
            return sev
    return "None"

# -----------------------------
# New Severity Enhancement Functions
# -----------------------------

def compute_severity_counts(parsed_vectors):
    counts = Counter()
    scores_by_severity = defaultdict(list)

    for v in parsed_vectors:
        if "metrics" in v and v["metrics"]:
            score = calculate_score(v["metrics"])
            severity = classify_severity(score)
            counts[severity] += 1
            scores_by_severity[severity].append(score)

    return counts, scores_by_severity

def compute_severity_percentages(counts, total):
    return {sev: f"{count} ({count / total * 100:.1f}%)" for sev, count in counts.items()}

def compute_severity_avg(scores_by_severity):
    return {sev: round(sum(scores)/len(scores), 2) if scores else 0.0
            for sev, scores in scores_by_severity.items()}

def compute_severity_min_max(scores_by_severity):
    return {sev: {"min": min(scores) if scores else 0.0,
                  "max": max(scores) if scores else 0.0}
            for sev, scores in scores_by_severity.items()}

def compute_score_histogram(parsed_vectors, step=0.5):
    histogram = Counter()
    for v in parsed_vectors:
        if "metrics" in v and v["metrics"]:
            score = calculate_score(v["metrics"])
            # round down to nearest step
            bucket = math.floor(score / step) * step
            histogram[bucket] += 1
    # sort by bucket
    return OrderedDict(sorted(histogram.items()))

# -----------------------------
# Main statistics function
# -----------------------------

def compute_statistics(parsed_vectors, mode="both", focus="all"):
    results = {"total": len(parsed_vectors)}

    if mode in ("severity", "both"):
        counts, scores_by_severity = compute_severity_counts(parsed_vectors)
        results["severity_counts"] = dict(counts)
        results["severity_percentages"] = compute_severity_percentages(counts, results["total"])
        results["severity_avg"] = compute_severity_avg(scores_by_severity)
        results["severity_min_max"] = compute_severity_min_max(scores_by_severity)
        results["score_histogram"] = dict(compute_score_histogram(parsed_vectors, step=0.5))

    if mode in ("metrics", "both"):
        metrics_counts = defaultdict(Counter)
        for v in parsed_vectors:
            for m, val in v["metrics"].items():
                if focus == "all" or focus == m:
                    metrics_counts[m][val] += 1
        results["metrics_distribution"] = {k: dict(v) for k, v in metrics_counts.items()}

    return results



# Add this new function
def compute_metrics_percentages(metrics_distribution, total):
    """Convert counts into count + percentage strings for each metric value."""
    metrics_percent = {}
    for metric, values in metrics_distribution.items():
        metrics_percent[metric] = {
            val: f"{count} ({count / total * 100:.1f}%)" for val, count in values.items()
        }
    return metrics_percent

# Update compute_statistics()
def compute_statistics(parsed_vectors, mode="both", focus="all"):
    results = {"total": len(parsed_vectors)}

    if mode in ("severity", "both"):
        counts, scores_by_severity = compute_severity_counts(parsed_vectors)
        results["severity_counts"] = dict(counts)
        results["severity_percentages"] = compute_severity_percentages(counts, results["total"])
        results["severity_avg"] = compute_severity_avg(scores_by_severity)
        results["severity_min_max"] = compute_severity_min_max(scores_by_severity)
        results["score_histogram"] = dict(compute_score_histogram(parsed_vectors, step=0.5))

    if mode in ("metrics", "both"):
        metrics_counts = defaultdict(Counter)
        for v in parsed_vectors:
            for m, val in v["metrics"].items():
                if focus == "all" or focus == m:
                    metrics_counts[m][val] += 1
        metrics_distribution = {k: dict(v) for k, v in metrics_counts.items()}
        results["metrics_distribution"] = metrics_distribution
        # Compute percentages
        results["metrics_percentages"] = compute_metrics_percentages(metrics_distribution, results["total"])

    return results
