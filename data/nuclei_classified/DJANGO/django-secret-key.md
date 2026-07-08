# Vulnerability: Django Secret Key Exposure
**Classification:** DJANGO
**Source:** Nuclei Template (`django-secret-key.yaml`)

## Description
The Django settings.py file containing a secret key was discovered. An attacker may use the secret key to bypass many security mechanisms and potentially obtain other sensitive configuration information (such as database password) from the settings file.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/manage.py
GET {{BaseURL}}/settings.py
GET {{BaseURL}}/app/settings.py
GET {{BaseURL}}/django/settings.py
GET {{BaseURL}}/settings/settings.py
GET {{BaseURL}}/web/settings/settings.py
GET {{BaseURL}}/{{app_name}}/settings.py
```

