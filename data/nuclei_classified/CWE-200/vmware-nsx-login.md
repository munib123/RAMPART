# Vulnerability: VMware NSX Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`vmware-nsx-login.yaml`)

## Description
VMware NSX login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login.jsp
```

