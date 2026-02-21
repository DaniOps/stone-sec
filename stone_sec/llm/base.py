from abc import ABC, abstractmethod
from typing import Dict


class LLMProvider(ABC):
    @abstractmethod
    def generate(self, prompt: str) -> Dict[str, str]:
        """
        Must return a dict with keys:
        - explanation
        - exploit_scenario
        - remediation
        """
        raise NotImplementedError