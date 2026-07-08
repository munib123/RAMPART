# Vulnerability: Note User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`note.yaml`)

## Description
Note user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://note.com/{{user}}
```

