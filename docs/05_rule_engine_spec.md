# Rule Interface

Each rule must implement:
* **rule_id**
* **severity**
* **detect(ast_tree, file_path)**

### Returns:
* `List[Finding]`

---

# Finding Model

### Attributes:
* **file**
* **line**
* **rule_id**
* **severity**
* **title**
* **snippet**
* **explanation** (optional)
* **exploit_scenario** (optional)
* **remediation** (optional)

---

# Rule Constraints
* Must rely only on AST
* Must not use LLM
* Must not alter global state
* Must be independently testable