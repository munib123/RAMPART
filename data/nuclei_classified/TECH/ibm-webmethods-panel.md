# Vulnerability: IBM webMethods Integration Login Panel - Detect
**Classification:** TECH
**Source:** Nuclei Template (`ibm-webmethods-panel.yaml`)

## Description
Identified an exposed IBM or Software AG webMethods login panel

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/wmroot/
GET {{BaseURL}}/integration/
```

