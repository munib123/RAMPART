# Vulnerability: Diablo User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`diablo.yaml`)

## Description
Diablo user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://diablo2.io/member/{{user}}/
```

