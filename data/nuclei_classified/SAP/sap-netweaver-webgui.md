# Vulnerability: SAP NetWeaver WebGUI Detection
**Classification:** SAP
**Source:** Nuclei Template (`sap-netweaver-webgui.yaml`)

## Description
Detection of SAP NetWeaver ABAP Webserver WebGUI

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/sap/bc/gui/sap/its/webgui
```

