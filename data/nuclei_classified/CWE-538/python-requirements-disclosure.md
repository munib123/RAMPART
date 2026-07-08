# Vulnerability: Python Requirements File Disclosure
**Classification:** CWE-538
**Source:** Nuclei Template (`python-requirements-disclosure.yaml`)

## Description
Detected Python requirements.txt file. This file contains Python package dependencies and versions that could reveal technology stack, vulnerable package versions, and internal dependencies.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/requirements.txt
GET {{BaseURL}}/requirements/requirements.txt
GET {{BaseURL}}/app/requirements.txt
GET {{BaseURL}}/src/requirements.txt
```

