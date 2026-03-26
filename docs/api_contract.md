# CodeShield API Contract

> ⚠️ This contract is shared across all teammates. Do NOT change field names or types without team agreement.

---

## POST `/analyze`

Analyzes source code for security vulnerabilities.

### Request

```json
{
  "language": "python",
  "filename": "app.py",
  "code": "query = 'SELECT * FROM users WHERE id=' + user_input"
}
```

| Field      | Type   | Required | Description                     |
|------------|--------|----------|---------------------------------|
| `language` | string | ✅        | Language of the code (e.g., `python`, `javascript`) |
| `filename` | string | ✅        | Name of the source file         |
| `code`     | string | ✅        | Full source code to analyze     |

---

### Response

```json
{
  "score": 42,
  "issues": [
    {
      "type": "sql_injection",
      "line": 3,
      "severity": "critical",
      "message": "User input concatenated directly into SQL query.",
      "simulation": "Input ' OR 1=1-- would return all rows from the database.",
      "ai_explanation": "This is vulnerable to SQL injection. Use parameterized queries instead.",
      "fix": "cursor.execute('SELECT * FROM users WHERE id=?', (user_input,))"
    }
  ]
}
```

| Field                    | Type     | Description                                      |
|--------------------------|----------|--------------------------------------------------|
| `score`                  | int (0–100) | Overall security score. Lower = more critical issues. |
| `issues`                 | array    | List of detected vulnerability objects           |
| `issues[].type`          | string   | Vulnerability category (`sql_injection`, `xss`, `hardcoded_secret`) |
| `issues[].line`          | int      | Line number to underline in the editor           |
| `issues[].severity`      | string   | `critical`, `high`, `medium`, `low`              |
| `issues[].message`       | string   | Short human-readable description for tooltip     |
| `issues[].simulation`    | string   | Safe text simulation of what an attacker could do |
| `issues[].ai_explanation`| string   | LLM-generated detailed explanation               |
| `issues[].fix`           | string   | Suggested safe code snippet                      |

---

## Severity Scale

| Severity   | Score Impact | Meaning                            |
|------------|--------------|------------------------------------|
| `critical` | -30          | Exploitable immediately            |
| `high`     | -20          | Serious risk, likely exploitable   |
| `medium`   | -10          | Moderate risk                      |
| `low`      | -5           | Minor issue or best-practice gap   |

---

## Error Response

```json
{
  "detail": "Invalid request: 'code' field is required."
}
```

HTTP Status: `422 Unprocessable Entity` for validation errors, `500` for internal errors.
