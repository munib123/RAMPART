# Vulnerability: Forumprawne.org User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`forumprawneorg.yaml`)

## Description
Forumprawne.org user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://forumprawne.org/members/{{user}}.html
```

