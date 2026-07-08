# Vulnerability: Cults3D User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`cults3d.yaml`)

## Description
Cults3D user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://cults3d.com/en/users/{{user}}/creations
```

