# Included in v1

## Language Support
* Python only

## Detection Engine
* AST-based rule detection
* Hardcoded rule set
* Deterministic severity mapping

## Initial Rules (v1)
* `eval()` usage
* `os.system()`
* `subprocess` with `shell=True`
* `pickle.loads`
* Hardcoded secrets (basic regex)
* Basic SQL injection pattern

---

## LLM Role
* Explain vulnerability
* Simulate exploit scenario
* Suggest remediation

### LLM does NOT:
* Detect vulnerabilities
* Assign severity
* Control exit codes

---

## CLI Commands
* `stone-sec review <path>`
* `stone-sec review <path> --json`
* `stone-sec review <path> --fail-on <severity>`
* `stone-sec version`

---

## Exit Codes
* **0** → No threshold breach
* **1** → Severity threshold exceeded

---

## Architecture Constraints
* Stateless
* No caching
* No telemetry
* No rule configuration system
* No plugin system
* No auto-fix

---

## Explicitly Out of Scope (v1)
* Multi-language support
* Taint tracking
* Data flow analysis
* Web dashboard
* SaaS backend
* Historical tracking
* Interactive terminal UI
* Plugin ecosystem
* AI-based severity scoring