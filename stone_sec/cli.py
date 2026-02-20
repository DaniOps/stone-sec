from stone_sec.engine.scanner import discover_python_files
import argparse
import sys
from pathlib import Path



def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="stone-sec",
        description="Local-first deterministic security code review CLI for Python."
    )

    subparsers = parser.add_subparsers(dest="command")

    # Review command
    review_parser = subparsers.add_parser(
        "review",
        help="Scan Python files for security issues."
    )

    review_parser.add_argument(
        "path",
        type=str,
        help="Path to Python file or directory to scan."
    )

    review_parser.add_argument(
        "--json",
        action="store_true",
        help="Output results in JSON format."
    )

    review_parser.add_argument(
        "--fail-on",
        type=str,
        choices=["low", "medium", "high", "critical"],
        help="Fail with exit code 1 if findings meet or exceed this severity."
    )

    review_parser.add_argument(
        "--provider",
        type=str,
        choices=["ollama", "openai", "anthropic"],
        default="ollama",
        help="LLM provider to use (default: ollama)."
    )

    # Version command
    subparsers.add_parser(
        "version",
        help="Show tool version."
    )

    return parser


def handle_review(args):
    target_path = Path(args.path)

    if not target_path.exists():
        print(f"[ERROR] Path does not exist: {target_path}")
        sys.exit(1)

    python_files = discover_python_files(target_path)

    if not python_files:
        print("No Python files found.")
        sys.exit(0)

    print(f"Discovered {len(python_files)} Python file(s):")
    for file in python_files:
        print(f" - {file}")

    print("\nRule engine not implemented yet.")
    print("0 findings.\n")

    sys.exit(0)


def handle_version():
    print("stone-sec version 0.1.0")
    sys.exit(0)


def main():
    parser = create_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    if args.command == "review":
        handle_review(args)

    elif args.command == "version":
        handle_version()

    else:
        parser.print_help()
        sys.exit(1)