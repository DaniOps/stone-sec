# High-Level Flow

CLI
 ↓
Scanner
 ↓
AST Parsing
 ↓
Rule Engine
 ↓
Findings Collection
 ↓
LLM Enhancement (optional)
 ↓
Formatter
 ↓
Exit Handler

---

# Directory Structure

```text
stone_sec/
    __init__.py
    cli.py

    engine/
        scanner.py
        rules.py
        severity.py

    llm/
        base.py
        ollama_provider.py
        openai_provider.py
        anthropic_provider.py

    formatters/
        terminal.py
        json_formatter.py

    models/
        finding.py

Core Principles:
CLI layer must not contain business logic

Rule engine must not depend on LLM

LLM layer must not control severity

Exit logic must be deterministic