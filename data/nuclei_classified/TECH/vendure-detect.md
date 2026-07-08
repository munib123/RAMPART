# Vulnerability: Vendure - Detect
**Classification:** TECH
**Source:** Nuclei Template (`vendure-detect.yaml`)

## Description
Vendure headless commerce platform was detected via the presence of the vendure-auth-token response header on the Shop API endpoint.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /shop-api HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"query":"{ __typename }"}
```

