# Vulnerability: Dell iDRAC6 - Detect
**Classification:** TECH
**Source:** Nuclei Template (`dell-idrac6-detect.yaml`)

## Description
Detected Integrated Dell Remote Access Controller. The iDRAC is designed for secure local and remote server management and helps IT administrators deploy, update and monitor Dell EMC PowerEdge servers.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/data?get=prodServerGen
```

