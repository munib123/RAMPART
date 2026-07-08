# Vulnerability: Crevado User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`crevado.yaml`)

## Description
Crevado user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://{{user}}.crevado.com/
```

