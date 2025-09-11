import argparse
from cvss_stats import parser, cvss_parser, stats, formatter

def run():

    print("""
  ____ _  _ ____ ____    ____ ___ ____ ___ ____    ___ ____ ____ _    
  |    |  | [__  [__     [__   |  |__|  |  [__      |  |  | |  | |    
  |___  \/  ___] ___]    ___]  |  |  |  |  ___]     |  |__| |__| |___ 
      
      By @EdgarHuemac
  """)
    print(' A tool designed to get statistics from bulk CVSS vectors. Designed for helping me do vuln management & pentesting reporting.')
    print(' IMPORTANT: Tool is still in development & testing, do not expect perfection. ')
    print('- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -')

    parser_cli = argparse.ArgumentParser(
        prog="cvss-stats",
        description="Analyze CVSS vectors and produce statistics."
    )

    parser_cli.add_argument(
        "--input",
        required=True,
        help="Path to input file containing CVSS vectors (one per line)."
    )
    parser_cli.add_argument(
        "--version",
        default="3.1",
        help="CVSS version (default: 3.1). Future: 3.0, 2.0, etc."
    )
    parser_cli.add_argument(
        "--output",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)."
    )
    parser_cli.add_argument(
        "--mode",
        choices=["severity", "metrics", "both"],
        default="both",
        help="Choose statistics mode: severity distribution, metric frequencies, or both."
    )
    parser_cli.add_argument(
        "--focus",
        choices=["all", "AV", "AC", "PR", "UI", "C", "I", "A"],
        default="all",
        help="Focus only on specific metric statistics (default: all)."
    )

    args = parser_cli.parse_args()

    raw_vectors = parser.load_file(args.input)
    parsed_vectors = cvss_parser.parse_vectors(raw_vectors, version=args.version)
    results = stats.compute_statistics(parsed_vectors, mode=args.mode, focus=args.focus)
    formatter.display_results(results, output_format=args.output)
