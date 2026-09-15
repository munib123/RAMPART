# Nuclei Template: Solar-Log 500 2.8.2 - Incorrect Access Control
**Template ID:** solar-log-authbypass
**Vulnerability Class:** Improper Access Control - Generic
**Severity:** High
**CWE:** CWE-284
**Source:** Nuclei Template (`solar-log-authbypass.yaml`)

## Vulnerability Information & PoC

## Description
Solar-Log 500 2.8.2 is susceptible to incorrect access control because the web administration server for Solar-Log 500 all versions prior to 2.8.2 Build 52 does not require authentication, which allows arbitrary remote attackers gain administrative privileges by connecting to the server.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/lan.html
```

## References
- https://www.exploit-db.com/exploits/49986
