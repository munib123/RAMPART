# Nuclei Template: Netsweeper 4.0.9 - Open Redirect
**Template ID:** netsweeper-open-redirect
**Vulnerability Class:** Open Redirect
**Severity:** Medium
**CWE:** CWE-601
**Source:** Nuclei Template (`netsweeper-open-redirect.yaml`)

## Vulnerability Information & PoC

## Description
Netsweeper 4.0.9 contains an open redirect vulnerability. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/webadmin/authportal/bounce.php?url=https://interact.sh/
```

## References
- https://packetstormsecurity.com/files/download/133034/netsweeper-issues.tgz
