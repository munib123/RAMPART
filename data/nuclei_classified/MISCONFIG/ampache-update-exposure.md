# Vulnerability: Ampache Update Page Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`ampache-update-exposure.yaml`)

## Description
Ampache update page is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/update.php
```

