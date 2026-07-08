# Vulnerability: Drupal Install
**Classification:** MISCONFIG
**Source:** Nuclei Template (`drupal-install.yaml`)

## Description
Drupal Install panel exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install.php?profile=default
GET {{BaseURL}}/core/install.php
```

