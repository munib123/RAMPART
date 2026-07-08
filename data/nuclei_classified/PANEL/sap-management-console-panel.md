# Vulnerability: SAP Management Console - Panel
**Classification:** PANEL
**Source:** Nuclei Template (`sap-management-console-panel.yaml`)

## Description
Detected the SAP Management Console (SAP MC) web panel by requesting /sapmc/sapmc.html and checking for a gSOAP server header the page title.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/sapmc/sapmc.html
```

