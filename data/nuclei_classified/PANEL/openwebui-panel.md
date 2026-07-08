# Vulnerability: Openweb UI Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`openwebui-panel.yaml`)

## Description
OpenWebUI was detected - a platform for running AI on your own terms

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/api/config
GET {{BaseURL}}/auth
GET {{BaseURL}}/opensearch.xml
```

