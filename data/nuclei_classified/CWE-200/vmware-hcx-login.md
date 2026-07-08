# Vulnerability: VMware HCX Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`vmware-hcx-login.yaml`)

## Description
VMware HCX login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/hybridity/ui/hcx-client/index.html
```

