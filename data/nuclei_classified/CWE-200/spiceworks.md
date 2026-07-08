# Vulnerability: SpiceWorks User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`spiceworks.yaml`)

## Description
SpiceWorks user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://community.spiceworks.com/people/{{user}}
```

