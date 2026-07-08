# Vulnerability: Sofurry User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`sofurry.yaml`)

## Description
Sofurry user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://{{user}}.sofurry.com
```

