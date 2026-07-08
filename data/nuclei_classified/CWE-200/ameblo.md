# Vulnerability: Ameblo User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`ameblo.yaml`)

## Description
Ameblo user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://ameblo.jp/{{user}}
```

