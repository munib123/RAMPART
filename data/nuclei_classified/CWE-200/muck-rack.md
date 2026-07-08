# Vulnerability: Muck Rack User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`muck-rack.yaml`)

## Description
Muck Rack user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://muckrack.com/{{user}}
```

