# Vulnerability: VMware vRealize
**Classification:** VMWARE
**Source:** Nuclei Template (`vmware-vrealize-detect.yaml`)

## Description
Version of VMware vRealize Operations Manager

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/ui/login.action
```

