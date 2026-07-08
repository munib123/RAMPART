# Vulnerability: Pastebin User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`pastebin.yaml`)

## Description
Pastebin user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://pastebin.com/u/{{user}}
```

