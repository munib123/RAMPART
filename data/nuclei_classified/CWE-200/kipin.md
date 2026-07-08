# Vulnerability: Kipin User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`kipin.yaml`)

## Description
Kipin user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://kipin.app/{{user}}
```

