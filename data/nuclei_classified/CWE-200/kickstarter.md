# Vulnerability: Kickstarter User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`kickstarter.yaml`)

## Description
Kickstarter user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.kickstarter.com/profile/{{user}}
```

