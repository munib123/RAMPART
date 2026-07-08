# Vulnerability: Flowcode User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`flowcode.yaml`)

## Description
Flowcode user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.flowcode.com/page/{{user}}
```

