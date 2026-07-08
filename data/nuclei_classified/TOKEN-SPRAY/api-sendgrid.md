# Vulnerability: Sendgrid API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-sendgrid.yaml`)

## Description
A REST-like interface that enables you to send email at scale, ensuring your application can handle high-volume email with ease.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.sendgrid.com/v3/scopes
```

