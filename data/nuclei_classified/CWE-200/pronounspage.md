# Vulnerability: Pronouns.Page User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`pronounspage.yaml`)

## Description
Pronouns.Page user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://pronouns.page/api/profile/get/{{user}}?version=2
```

