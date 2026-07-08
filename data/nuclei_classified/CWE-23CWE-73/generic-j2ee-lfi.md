# Vulnerability: Generic J2EE LFI Scan Panel - Detect
**Classification:** CWE-23,CWE-73
**Source:** Nuclei Template (`generic-j2ee-lfi.yaml`)

## Description
Generic J2EE Scan panel was detected. Looks for J2EE specific LFI vulnerabilities; tries to leak the web.xml file.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}{{paths}}
```

