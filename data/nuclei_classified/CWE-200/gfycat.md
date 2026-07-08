# Vulnerability: Gfycat User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`gfycat.yaml`)

## Description
Gfycat user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://gfycat.com/@{{user}}
```

