# Vulnerability: OAuth 2.0 Authorization Server Detection Template
**Classification:** TECH
**Source:** Nuclei Template (`oauth2-detect.yaml`)

## Description
Try to detect OAuth 2.0 Authorization Server via the "oauth/token" endpoint

## Vulnerable Code Pattern / Exploit Payload
```http
POST {{BaseURL}}/oauth/token
```

