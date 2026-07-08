# Vulnerability: Nginx Test Page for OpenCloudOS
**Classification:** TECH
**Source:** Nuclei Template (`nginx-opencloudos-test-page.yaml`)

## Description
OpenCloudOS test page was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

