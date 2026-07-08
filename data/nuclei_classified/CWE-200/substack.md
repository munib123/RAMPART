# Vulnerability: substack.com User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`substack.yaml`)

## Description
substack.com user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://substack.com/@{{user}}
```

