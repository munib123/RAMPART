# Vulnerability: VMware Cloud Director Availability Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`vmware-cloud-availability.yaml`)

## Description
VMware Cloud Director Availability login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/ui/login
```

