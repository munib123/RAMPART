# Vulnerability: ANobii User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`anobii.yaml`)

## Description
ANobii user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.anobii.com/{{user}}/profile/activity
```

