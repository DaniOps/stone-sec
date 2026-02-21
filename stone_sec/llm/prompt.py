from stone_sec.models.finding import Finding


def build_prompt(finding: Finding) -> str:
    """
    Build a strict JSON-only prompt for the LLM.
    """
    return f"""
You are a security analysis engine.

Analyze the following security finding and return ONLY valid JSON with keys:
- explanation
- exploit_scenario
- remediation

Finding details:
- Title: {finding.title}
- Severity: {finding.severity}
- File: {finding.file}
- Line: {finding.line}
- Code Snippet: {finding.snippet}

Rules:
- Do not include any text outside JSON
- Do not change severity
- Do not invent vulnerabilities
"""