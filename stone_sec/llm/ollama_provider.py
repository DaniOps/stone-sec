import json
import subprocess
from typing import Dict

from stone_sec.llm.base import LLMProvider


class OllamaProvider(LLMProvider):
    def __init__(self, model: str = "llama3"):
        self.model = model

    def generate(self, prompt: str) -> Dict[str, str]:
        try:
            proc = subprocess.run(
    ["ollama", "run", self.model],
    input=prompt,
    capture_output=True,
    text=True,
    encoding="utf-8",
    errors="ignore",
    timeout=120,
)
            output = proc.stdout.strip()
            data = json.loads(output)

            return {
                "explanation": data.get("explanation", ""),
                "exploit_scenario": data.get("exploit_scenario", ""),
                "remediation": data.get("remediation", ""),
            }
        except Exception:
            # Never crash — fallback
            return {
                "explanation": "Potential security risk detected.",
                "exploit_scenario": "An attacker could abuse this behavior if input is controlled.",
                "remediation": "Avoid unsafe constructs and validate inputs.",
            }