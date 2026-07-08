# Vulnerability: AlienVault Open Threat Exchange (OTX) API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-alienvault.yaml`)

## Description
IP/domain/URL reputation

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://otx.alienvault.com/api/v1/pulses/subscribed?page=1 HTTP/1.1
Host: otx.alienvault.com
X-OTX-API-KEY: {{token}}
```

