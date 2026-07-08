# Vulnerability: Django Debug Exposure
**Classification:** DJANGO
**Source:** Nuclei Template (`django-debug-exposure.yaml`)

## Description
Django debug mode enabled exposes internal information.

## Vulnerable Code Pattern / Exploit Payload
```http
POST {{BaseURL}}/admin/login/?next=/admin/
```

