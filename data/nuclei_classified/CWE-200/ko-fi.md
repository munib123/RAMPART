# Vulnerability: Ko-Fi User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`ko-fi.yaml`)

## Description
Ko-Fi user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://ko-fi.com/{{user}}
```

