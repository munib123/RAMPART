# Vulnerability: Akamai Bot Manager Protection - Detect
**Classification:** AKAMAI
**Source:** Nuclei Template (`akamai-bot-manager-detect.yaml`)

## Description
Checks if the website is protected by Akamai Bot Manager

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

