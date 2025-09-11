--- Development plan ---

cvss_stats_tool/
│
├── cvss_stats/                # Main package
│   ├── __init__.py
│   ├── cli.py                 # Argument parsing, entry point logic
│   ├── parser.py              # Input file parsing (txt for now, later json, csv, etc.)
│   ├── cvss_parser.py         # CVSS vector parsing (specific to CVSS 3.1 now, future expandable)
│   ├── stats.py               # Core statistics and aggregation logic
│   ├── formatter.py           # Output formatting (plain text, tables, json export later)
│   └── utils.py               # Helpers, constants, shared stuff
│
├── tests/                     # Unit tests
│   ├── test_parser.py
│   ├── test_cvss_parser.py
│   ├── test_stats.py
│   └── ...
│
├── data/                      # Sample input files for testing/demo
│   └── sample_vectors.txt
│
├── main.py                    # Entry point for running `python main.py`
│
├── requirements.txt           # Dependencies
└── README.md                  # Project documentation
