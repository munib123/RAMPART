# Vulnerability: SendGrid Env File Exposure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`sendgrid-env.yaml`)

## Description
SendGrid file is exposed containing environment variables.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/sendgrid.env
```

