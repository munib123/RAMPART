# Vulnerability: Resumes actorsaccess User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`resumes-actorsaccess.yaml`)

## Description
Resumes actorsaccess user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://resumes.actorsaccess.com/{{user}}
```

