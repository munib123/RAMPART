# Vulnerability: KCFinder - Exposure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`kcfinder-exposure.yaml`)

## Description
Detected publicly accessible KCFinder instances that may have allowed arbitrary file uploads and remote code execution (RCE).Exposure of KCFinder could have allowed an attacker to gain unauthorized access to the file manager and upload malicious files.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/kcfinder/browse.php
GET {{BaseURL}}/assets/kcfinder/browse.php
GET {{BaseURL}}/lib/kcfinder/browse.php
GET {{BaseURL}}/admin/kcfinder/browse.php
GET {{BaseURL}}/includes/kcfinder/browse.php
```

