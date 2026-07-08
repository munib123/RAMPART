# Vulnerability: UniGUI Framework - Detect
**Classification:** TECH
**Source:** Nuclei Template (`uni-gui-framework.yaml`)

## Description
Checks for the presence of UniGUI framework and extracts its version along with the Sencha Ext JS version.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

