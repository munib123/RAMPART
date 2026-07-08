# Vulnerability: Shanii Writes User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`shanii-writes.yaml`)

## Description
Shanii Writes user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://forum.shanniiwrites.com/u/{{user}}/summary.json
```

