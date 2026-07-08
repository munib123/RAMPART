# Vulnerability: Gunicorn Config File - File Disclosure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`gunicorn-config-file.yaml`)

## Description
Gunicorn Config file is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/gunicorn.conf.py
```

