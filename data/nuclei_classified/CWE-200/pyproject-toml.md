# Vulnerability: pyproject.toml Configuration - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`pyproject-toml.yaml`)

## Description
pyproject.toml configuration was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/pyproject.toml
```

