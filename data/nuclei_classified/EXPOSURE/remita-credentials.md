# Vulnerability: Remita Merchant ID & API Key - Exposure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`remita-credentials.yaml`)

## Description
Detected exposed Remita merchant IDs, API keys, and secret hashes in application source code, configuration files, or publicly accessible assets.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

