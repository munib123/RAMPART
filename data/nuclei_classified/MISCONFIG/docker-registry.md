# Vulnerability: Docker Registry Listing
**Classification:** MISCONFIG
**Source:** Nuclei Template (`docker-registry.yaml`)

## Description
Docker Registry Listing enabled.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/v2/_catalog
```

