# Vulnerability: Msmtp - Config Exposure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`msmtp-config.yaml`)

## Description
Msmtp configuration was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.msmtprc
```

