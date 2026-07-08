# Vulnerability: Django Debug Configuration Enabled
**Classification:** DJANGO
**Source:** Nuclei Template (`django-debug-config-enabled.yaml`)

## Description
Django debug configuration is enabled, which allows an attacker to obtain system configuration information such as paths or settings.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/NON_EXISTING_PATH/
```

