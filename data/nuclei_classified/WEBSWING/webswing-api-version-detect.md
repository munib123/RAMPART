# Vulnerability: WebSwing REST API Version - Detection
**Classification:** WEBSWING
**Source:** Nuclei Template (`webswing-api-version-detect.yaml`)

## Description
WebSwing REST API version via the /rest/version endpoint.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/rest/version
```

