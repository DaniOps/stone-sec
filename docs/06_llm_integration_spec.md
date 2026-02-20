# Provider Abstraction

## Base Interface

```python
class LLMProvider:
    def generate(prompt: str) -> dict:
        pass
```

## Default Provider

- Ollama

## Optional Providers

- OpenAI
- Anthropic

## Prompt Requirements

Model must return structured JSON:

```json
{
  "explanation": "...",
  "exploit_scenario": "...",
  "remediation": "..."
}
```

If parsing fails:

- Fallback to static explanation template
- Never crash

## LLM Guardrails

- No severity modification
- No exit control
- No rule suggestion
- No detection logic
