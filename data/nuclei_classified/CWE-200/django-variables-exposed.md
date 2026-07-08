# Vulnerability: Django Config - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`django-variables-exposed.yaml`)

## Description
Django configuration information was detected, which could reveal web application framework exceptions that could indicate exploitation attempts.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

