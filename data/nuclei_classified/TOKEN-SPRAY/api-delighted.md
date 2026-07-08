# Vulnerability: Delighted API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-delighted.yaml`)

## Description
Collect customer feedback in minutes

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.delighted.com/v1/metrics.json
```

