# Vulnerability: VMware Site Recovery Manager Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`vmware-site-recovery-manager.yaml`)

## Description
VMware Site Recovery Manger panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/configure/app/landing/welcome-srm-va.html
```

