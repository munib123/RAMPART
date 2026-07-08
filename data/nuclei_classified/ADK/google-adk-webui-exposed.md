# Vulnerability: Google ADK Development UI Exposure
**Classification:** ADK
**Source:** Nuclei Template (`google-adk-webui-exposed.yaml`)

## Description
Detects the exposure of the Google Agent Development Kit (ADK) Development UI, which may lead to sensitive information disclosure or unauthorized access.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/dev-ui/
```

