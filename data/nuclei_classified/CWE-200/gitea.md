# Vulnerability: Gitea User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`gitea.yaml`)

## Description
Gitea user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://gitea.com/{{user}}
```

