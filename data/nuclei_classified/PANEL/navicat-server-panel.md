# Vulnerability: Navicat On-Prem Server Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`navicat-server-panel.yaml`)

## Description
Navicat On-Prem Server is an on-premise solution that provides you with the option to host a cloud environment for storing Navicat objects internally at your location. In our On-Prem environment, you can enjoy complete control over your system and maintain 100% privacy. It is secure and reliable that allow you to maintain a level of control that the cloud often cannot.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/login
```

