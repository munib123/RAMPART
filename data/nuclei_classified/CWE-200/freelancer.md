# Vulnerability: Freelancer User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`freelancer.yaml`)

## Description
Freelancer user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.freelancer.com/u/{{user}}
```

