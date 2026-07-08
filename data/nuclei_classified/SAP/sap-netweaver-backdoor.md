# Vulnerability: SAP NetWeaver - Backdoor Detection
**Classification:** SAP
**Source:** Nuclei Template (`sap-netweaver-backdoor.yaml`)

## Description
Detected a potential backdoor in SAP NetWeaver allowing unauthorized command execution.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/irj/helper.jsp?cmd=ls
GET {{BaseURL}}/irj/cache.jsp?cmd=ls
```

