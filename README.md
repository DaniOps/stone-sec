# Stone-Sec

Local-first, CI-safe Python security scanner with optional AI explanations.

## Why Stone-Sec
- Deterministic static analysis
- Predictable CI behavior
- No cloud dependency
- AI used only for explanation, never decisions

## Development Installation
pip install stone-sec

## Basic Usage
stone-sec review path/

## CI Enforcement
stone-sec review path/ --fail-on high

## JSON Output
stone-sec review path/ --format json

## AI Explanations (Optional)
stone-sec review path/ --provider ollama

## GitHub Actions (CI)

Run Stone-Sec automatically in GitHub Actions to enforce security checks.

```yaml
- name: Run Stone-Sec
  uses: DaniOps/stone-sec@v1
  with:
    path: .
    fail_on: high
```

## Environment Check
stone-sec doctor

## Design Philosophy
- Detection is deterministic
- AI is enhancement-only
- Exit codes drive CI
- Local-first by default

## License
MIT
