# Vulnerability: RDWeb RemoteApp and Desktop Connections - Web Access
**Classification:** CWE-200
**Source:** Nuclei Template (`workresources-rdp.yaml`)

## Description
RDWeb RemoteApp and Desktop Connections does not display.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/RDWeb/Pages/en-US/login.aspx
```

