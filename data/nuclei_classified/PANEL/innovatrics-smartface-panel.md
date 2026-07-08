# Vulnerability: Unauthenticated SmartFace Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`innovatrics-smartface-panel.yaml`)

## Description
An unauthenticated SmartFace login was detected. The panel, used for facial recognition from video streams, allowed attackers to extract camera connection strings and other sensitive information

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
POST /-/graphql HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"query":"query getIsCollectingData {\n  isCollectingData\n}","operationName":"getIsCollectingData","variables":{}}
```

