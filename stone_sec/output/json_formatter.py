import json
from typing import List
from stone_sec.models.finding import Finding


def findings_to_json(findings: List[Finding]) -> str:
    data = []

    for f in findings:
        data.append(
            {
                "rule_id": f.rule_id,
                "severity": str(f.severity),
                "title": f.title,
                "file": str(f.file),
                "line": f.line,
                "snippet": f.snippet,
                "explanation": f.explanation,
                "exploit_scenario": f.exploit_scenario,
                "remediation": f.remediation,
            }
        )

    return json.dumps(
        {
            "total_findings": len(findings),
            "findings": data,
        },
        indent=2,
    )