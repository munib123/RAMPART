# Vulnerability: Metasploit Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`metasploit-panel.yaml`)

## Description
Metasploit Web Panel is detected

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login
```

