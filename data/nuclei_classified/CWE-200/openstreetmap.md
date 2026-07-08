# Vulnerability: OpenStreetMap User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`openstreetmap.yaml`)

## Description
OpenStreetMap user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.openstreetmap.org/user/{{user}}
```

