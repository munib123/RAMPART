# Vulnerability: Fortinet FortiAnalyzer - Login Panel
**Classification:** PANEL
**Source:** Nuclei Template (`fortinet-fortianalyzer-panel.yaml`)

## Description
Fortinet FortiAnalyzer is a centralised log management and analytics platform for
Fortinet security devices. The web management console is commonly internet-exposed
on ports 443, 10443, 9443, or 4443.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

