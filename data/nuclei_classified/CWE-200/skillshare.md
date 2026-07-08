# Vulnerability: Skill Share User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`skillshare.yaml`)

## Description
Skill Share user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.skillshare.com/en/user/{{user}}
```

