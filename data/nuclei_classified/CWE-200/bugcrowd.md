# Vulnerability: Bugcrowd User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`bugcrowd.yaml`)

## Description
Bugcrowd user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://bugcrowd.com/{{user}}
```

