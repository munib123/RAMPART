# Vulnerability: Honeywell Excel Web Control Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`honeywell-web-controller.yaml`)

## Description
Honeywell Excel Web Control login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/standard/default.php
```

