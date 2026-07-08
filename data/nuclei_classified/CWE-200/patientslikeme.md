# Vulnerability: PatientsLikeMe User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`patientslikeme.yaml`)

## Description
PatientsLikeMe user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.patientslikeme.com/members/{{user}}
```

