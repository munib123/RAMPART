# Nuclei Template: Rockwell Automation TCP/IP Configuration Information - Detect
**Template ID:** tcpconfig
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`tcpconfig.yaml`)

## Vulnerability Information & PoC

## Description
TCP/IP configuration information was detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/tcpconfig.html
```

## References
- https://www.rockwellautomation.com/
- https://www.exploit-db.com/ghdb/6782
