# Vulnerability: Dateinasia User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`dateinasia.yaml`)

## Description
Dateinasia user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.dateinasia.com/{{user}}
```

