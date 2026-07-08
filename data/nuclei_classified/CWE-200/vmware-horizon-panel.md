# Vulnerability: VMware Horizon Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`vmware-horizon-panel.yaml`)

## Description
VMware Horizon login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/portal/webclient/index.html
```

