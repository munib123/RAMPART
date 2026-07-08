# Vulnerability: MeteoBridge - Detect
**Classification:** METEOBRIDGE
**Source:** Nuclei Template (`meteobridge-detect.yaml`)

## Description
Exposed MeteoBridge devices by identifying their unique HTTP response patterns.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/cgi-bin/meteobridge.cgi
```

