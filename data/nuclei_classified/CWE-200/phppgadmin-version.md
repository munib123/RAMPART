# Vulnerability: PhpPgAdmin Version Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`phppgadmin-version.yaml`)

## Description
PhpPgAdmin version information was detected via the intro.php file.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/phppgadmin/intro.php
```

