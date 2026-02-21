from importlib.metadata import version, PackageNotFoundError
from stone_sec.llm.ollama_provider import OllamaProvider
from stone_sec.llm.prompt import build_prompt
from stone_sec.engine.rules.runner import run_rules
from stone_sec.engine.parser import parse_python_file
from stone_sec.engine.rules.eval_rule import EvalUsageRule
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
    "--format",
    choices=["text", "json"],
    default="text",
    help="Output format (text or json)",
)

    review_parser.add_argument(
        "--fail-on",
        type=str,
        choices=["low", "medium", "high", "critical"],
        help="Fail with exit code 1 if findings meet or exceed this severity."
    )

    review_parser.add_argument(
    "--provider",
    choices=["ollama"],
    help="LLM provider for enhanced explanations",
)

    # Version command
    subparsers.add_parser(
        "version",
        help="Show tool version."
    )

    return parser


def handle_review(args):
    import sys
    from pathlib import Path

    from stone_sec.engine.severity import Severity
    from stone_sec.engine.scanner import discover_python_files
    from stone_sec.engine.parser import parse_python_file
    from stone_sec.engine.rules.runner import run_rules
    from stone_sec.llm.ollama_provider import OllamaProvider
    from stone_sec.llm.prompt import build_prompt
    from stone_sec.output.json_formatter import findings_to_json

    target_path = Path(args.path)

    if not target_path.exists():
        print(f"[ERROR] Path does not exist: {target_path}")
        sys.exit(1)

    python_files = discover_python_files(target_path)

    if not python_files:
        if args.format == "json":
            print(findings_to_json([]))
        else:
            print("No Python files found.")
        sys.exit(0)

    findings = []

    # --- Deterministic detection phase ---
    for file_path in python_files:
        tree = parse_python_file(file_path)
        if tree is None:
            continue

        findings.extend(run_rules(tree, file_path))

    if not findings:
        if args.format == "json":
            print(findings_to_json([]))
        else:
            print("No security issues found.")
        sys.exit(0)

    # --- Optional LLM enhancement (never affects severity/exit) ---
    provider = None
    if getattr(args, "provider", None) == "ollama":
        provider = OllamaProvider()

    if provider:
        for f in findings:
            prompt = build_prompt(f)
            result = provider.generate(prompt)

            f.explanation = result.get("explanation")
            f.exploit_scenario = result.get("exploit_scenario")
            f.remediation = result.get("remediation")

    # --- Output phase ---
    if args.format == "json":
        print(findings_to_json(findings))
    else:
        print(f"Found {len(findings)} issue(s):\n")

        for f in findings:
            print(f"[{str(f.severity)}] {f.title}")
            print(f"Rule: {f.rule_id}")
            print(f"File: {f.file}")
            print(f"Line: {f.line}")
            print(f"Snippet: {f.snippet}")

            if f.explanation:
                print(f"Explanation: {f.explanation}")
            if f.exploit_scenario:
                print(f"Exploit: {f.exploit_scenario}")
            if f.remediation:
                print(f"Fix: {f.remediation}")

            print()

    # --- CI fail-on logic (deterministic, unaffected by LLM/output) ---
    highest_severity = None
    for f in findings:
        if highest_severity is None or f.severity.value > highest_severity.value:
            highest_severity = f.severity

    if args.fail_on:
        threshold = Severity.from_string(args.fail_on)
        if highest_severity and highest_severity.value >= threshold.value:
            sys.exit(1)

    sys.exit(0)


def handle_version(args):
    try:
        v = version("stone-sec")
    except PackageNotFoundError:
        v = "unknown"
    print(f"stone-sec version {v}")


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