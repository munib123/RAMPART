# Vulnerability: GitLab User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`gitlab.yaml`)

## Description
GitLab user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://gitlab.com/{{user}}
```

