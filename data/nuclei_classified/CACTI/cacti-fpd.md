# Vulnerability: Cacti - Full Path Disclosure
**Classification:** CACTI
**Source:** Nuclei Template (`cacti-fpd.yaml`)

## Description
Detected a Full Path Disclosure (FPD) in Cacti when the log file is not writable. The error message reveals the absolute path of the log file on the server.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/cacti/
GET {{BaseURL}}/index.php
GET {{BaseURL}}/cacti/index.php
```

