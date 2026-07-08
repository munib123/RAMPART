# Vulnerability: Hashnode User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`hashnode.yaml`)

## Description
hashnode.com user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://hashnode.com/@{{user}}
```

