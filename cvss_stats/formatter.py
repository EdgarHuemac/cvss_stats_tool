import json

def display_results(results, output_format="table"):
    if output_format == "json":
        print(json.dumps(results, indent=2))
    else:
        # Table / console output
        print(f"Total vulnerabilities: {results['total']}\n")

        # -----------------------------
        # Severity Statistics
        # -----------------------------
        if "severity_counts" in results:
            print("Severity distribution:")
            sev_list = sorted(results['severity_counts'].keys())
            for sev in sev_list:
                count = results['severity_counts'].get(sev, 0)
                pct = results['severity_percentages'].get(sev, "0 (0.0%)")
                avg = results.get("severity_avg", {}).get(sev, 0.0)
                min_max = results.get("severity_min_max", {}).get(sev, {"min":0.0, "max":0.0})
                print(f"  {sev}: {count} ({pct.split('(')[1]}) | Avg: {avg} | Min: {min_max['min']} | Max: {min_max['max']}")

            # Score histogram
            if "score_histogram" in results:
                print("\nScore histogram (bucketed by 0.5):")
                for bucket, count in results["score_histogram"].items():
                    print(f"  {bucket}: {count}")

        # -----------------------------
        # Metrics Statistics
        # -----------------------------
        if "metrics_distribution" in results:
            print("\nMetrics distribution:")
            for metric, values in results["metrics_distribution"].items():
                print(f"  {metric}:")
                for val, count in values.items():
                    pct = results.get("metrics_percentages", {}).get(metric, {}).get(val, f"{count} (0.0%)")
                    print(f"    {val}: {pct}")
