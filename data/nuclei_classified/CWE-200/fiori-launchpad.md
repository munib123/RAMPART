# Vulnerability: Fiori Launchpad Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`fiori-launchpad.yaml`)

## Description
Fiori Launchpad login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/sap/bc/ui5_ui5/ui2/ushell/shells/abap/FioriLaunchpad.html
```

