# Vulnerability: Skyrock User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`skyrock.yaml`)

## Description
Skyrock user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://{{user}}.skyrock.com/
```

