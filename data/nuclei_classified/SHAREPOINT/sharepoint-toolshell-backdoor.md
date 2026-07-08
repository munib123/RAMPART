# Vulnerability: SharePoint Webshell - ToolShell
**Classification:** SHAREPOINT
**Source:** Nuclei Template (`sharepoint-toolshell-backdoor.yaml`)

## Description
Detects a persistent webshell named 'spinstall0.aspx' deployed on Microsoft SharePoint servers.
This file exposes sensitive cryptographic machineKey values from the SharePoint configuration,
indicating the presence of a ToolShell backdoor implant. This implant is linked to targeted
post-auth RCE campaigns exploiting CVE-2025-53770.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/_layouts/15/spinstall0.aspx
```

