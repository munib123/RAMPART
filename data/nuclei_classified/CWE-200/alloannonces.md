# Vulnerability: Alloannonces User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`alloannonces.yaml`)

## Description
Alloannonces user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.alloannonces.ma/{{user}}/
```

