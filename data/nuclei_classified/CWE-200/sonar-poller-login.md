# Vulnerability: Sonar Poller Login - Panel Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`sonar-poller-login.yaml`)

## Description
Sonar Poller login/interface was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

