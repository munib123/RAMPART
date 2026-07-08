# Vulnerability: Championat User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`championat.yaml`)

## Description
Championat user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.championat.com/user/{{user}}/
```

