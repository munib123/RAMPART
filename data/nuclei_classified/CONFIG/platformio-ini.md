# Vulnerability: Platformio Config File Disclosure
**Classification:** CONFIG
**Source:** Nuclei Template (`platformio-ini.yaml`)

## Description
“platformio.ini” (Project Configuration File) was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/platformio.ini
```

