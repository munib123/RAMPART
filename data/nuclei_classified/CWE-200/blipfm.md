# Vulnerability: BLIP.fm User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`blipfm.yaml`)

## Description
BLIP.fm user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://blip.fm/{{user}}
```

