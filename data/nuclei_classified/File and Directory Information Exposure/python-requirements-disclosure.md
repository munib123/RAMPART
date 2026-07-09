# Nuclei Template: Python Requirements File Disclosure
**Template ID:** python-requirements-disclosure
**Vulnerability Class:** File and Directory Information Exposure
**Severity:** Low
**CWE:** CWE-538
**Source:** Nuclei Template (`python-requirements-disclosure.yaml`)

## Vulnerability Information & PoC

## Description
Detected Python requirements.txt file. This file contains Python package dependencies and versions that could reveal technology stack, vulnerable package versions, and internal dependencies.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/requirements.txt
GET {{BaseURL}}/requirements/requirements.txt
GET {{BaseURL}}/app/requirements.txt
GET {{BaseURL}}/src/requirements.txt
```

## References
- https://pip.pypa.io/en/stable/reference/requirements-file-format/
