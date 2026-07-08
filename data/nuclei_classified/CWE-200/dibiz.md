# Vulnerability: DIBIZ User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`dibiz.yaml`)

## Description
DIBIZ user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.dibiz.com/{{user}}
```

