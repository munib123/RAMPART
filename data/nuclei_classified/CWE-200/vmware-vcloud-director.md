# Vulnerability: VMware vCloud Director Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`vmware-vcloud-director.yaml`)

## Description
VMware vCloud Director panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/cloud/
```

