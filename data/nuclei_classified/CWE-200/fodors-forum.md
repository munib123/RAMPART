# Vulnerability: Fodors Forum User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`fodors-forum.yaml`)

## Description
Fodors Forum user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.fodors.com/community/profile/{{user}}/forum-activity
```

