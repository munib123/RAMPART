# Vulnerability: Bonga cams User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`bonga-cams.yaml`)

## Description
Bonga cams user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://pt.bongacams.com/{{user}}
```

