# Vulnerability: InkBunny User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`inkbunny.yaml`)

## Description
InkBunny user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://inkbunny.net/{{user}}
```

