# Vulnerability: Detect Dell iDRAC8
**Classification:** TECH
**Source:** Nuclei Template (`dell-idrac8-detect.yaml`)

## Description
Detected The Integrated Dell Remote Access Controller, (iDRAC) is designed for secure local and remote server management and helps IT administrators deploy, update and monitor Dell EMC PowerEdge servers.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/data?get=prodServerGen
```

