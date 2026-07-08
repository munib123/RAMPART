# Vulnerability: Detect Dell iDRAC9
**Classification:** TECH
**Source:** Nuclei Template (`dell-idrac9-detect.yaml`)

## Description
The Integrated Dell Remote Access Controller (iDRAC) is designed for secure local and remote server management and helps IT administrators deploy, update and monitor Dell EMC PowerEdge servers.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/sysmgmt/2015/bmc/info
```

