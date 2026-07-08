# Vulnerability: Dot Credentials - Exposure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`dot-credentials-exposure.yaml`)

## Description
Detected the presence of a .credentials file and extracts sensitive authentication tokens, passwords, or API keys.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.credentials
```

