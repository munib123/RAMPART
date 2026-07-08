# Vulnerability: VMware Cloud Director Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`vmware-cloud-director.yaml`)

## Description
VMware Cloud Director login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login/
```

