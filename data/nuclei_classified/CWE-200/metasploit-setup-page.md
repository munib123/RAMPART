# Vulnerability: Metasploit Setup and Configuration Page - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`metasploit-setup-page.yaml`)

## Description
Metasploit setup and configuration page was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/users/new
```

