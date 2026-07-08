# Vulnerability: Python Setup Configuration - Exposure
**Classification:** PYTHON
**Source:** Nuclei Template (`python-setup-config.yaml`)

## Description
Python Setup Configuration "setup.py" File was exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/setup.py
```

