# Vulnerability: Python Virtual Environment  Directory Exposure
**Classification:** VENV
**Source:** Nuclei Template (`python-venv-exposure.yaml`)

## Description
An exposed Python virtual environment directory allows public access to internal files like pyvenv.cfg, installed packages, and configurations. This can leak sensitive information and aid attackers in identifying or exploiting vulnerabilities.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/venv/
```

