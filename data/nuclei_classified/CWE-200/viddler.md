# Vulnerability: Viddler User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`viddler.yaml`)

## Description
Viddler user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.viddler.com/channel/{{user}}/
```

