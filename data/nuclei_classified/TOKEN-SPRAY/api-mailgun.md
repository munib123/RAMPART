# Vulnerability: Mailgun API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-mailgun.yaml`)

## Description
Email Service

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.mailgun.net/v3/domains
```

