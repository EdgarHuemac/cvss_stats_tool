# CVSS Stats Tool

`cvss_stats_tool` is a simple, modular Python console tool for analyzing CVSS (Common Vulnerability Scoring System) vectors. It is designed for cybersecurity professionals, penetration testers, and security analysts who want to quickly generate statistics and insights from a list of CVSS 3.1 vectors.  

The tool is lightweight, modular, and easily extendable, making it a practical addition to any security toolkit or coding portfolio.

---

## Features

- **Input:** Accepts a list of CVSS vectors from a `.txt` file (one vector per line).  
- **Severity Analysis:**  
  - Counts and percentages per severity category (Low, Medium, High, Critical)  
  - Average base score per severity  
  - Minimum and maximum scores per severity  
  - Score histogram (bucketed by 0.5 increments)  
- **Metric Analysis:**  
  - Counts and percentages of individual CVSS metrics (AV, AC, PR, UI, S, C, I, A)  
- **Flexible Output:**  
  - JSON format for structured data  
  - Table format for human-readable console output  
- **Mode Options:**  
  - `--mode severity` → severity stats only  
  - `--mode metrics` → metric stats only  
  - `--mode both` → full analysis  

---

## Usage

```bash
python main.py --input data/sample_vectors.txt --mode both --output table
--input → Path to the input file containing CVSS vectors
--mode → Choose between severity, metrics, or both
--output → Choose output format: table or json


## Future Enhancements

  - Support for additional CVSS versions beyond 3.1
  - Cross-metric analysis (e.g., distribution of metrics within High severity vectors)
  - Graphical output (charts, histograms)
  - Custom metric focus with detailed statistics
  - Input from multiple formats (.json, .csv, .cvss)
  - Integration with vulnerability databases for automated analysis