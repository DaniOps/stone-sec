# Behavior

## Running
`stone-sec`  
→ Shows help only.

## review Command
`stone-sec review <path>`

### Options:
* `--json`
* `--fail-on <low|medium|high|critical>`
* `--provider <ollama|openai|anthropic>`

---

## Severity Ordering
`LOW < MEDIUM < HIGH < CRITICAL`

---

## Exit Code Logic
```python
if highest_severity >= threshold:
    exit(1)
else:
    exit(0)
    
Deterministic only.