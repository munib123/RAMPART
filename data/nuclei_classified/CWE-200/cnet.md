# Vulnerability: Cnet User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`cnet.yaml`)

## Description
Cnet user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.cnet.com/profiles/{{user}}/
```

