# Stone-Sec

Local-first, CI-safe Python security scanner with optional AI explanations.

## Why Stone-Sec
- Deterministic static analysis
- Predictable CI behavior
- No cloud dependency
- AI used only for explanation, never decisions

## Installation
pip install -e .

## Basic Usage
stone-sec review path/

## CI Enforcement
stone-sec review path/ --fail-on high

## JSON Output
stone-sec review path/ --format json

## AI Explanations (Optional)
stone-sec review path/ --provider ollama

## Environment Check
stone-sec doctor

## Design Philosophy
- Detection is deterministic
- AI is enhancement-only
- Exit codes drive CI
- Local-first by default

## License
MIT