# Vulnerability: Adminer Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`adminer-panel.yaml`)

## Description
An Adminer login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/adminer.php
GET {{BaseURL}}/_adminer.php
GET {{BaseURL}}/adminer/
GET {{BaseURL}}/editor.php
GET {{BaseURL}}/mysql.php
GET {{BaseURL}}/sql.php
GET {{BaseURL}}/wp-content/plugins/adminer/adminer.php
GET {{BaseURL}}/admin.php
GET {{BaseURL}}/modules/sfkdbmanage/adminer.php
```

