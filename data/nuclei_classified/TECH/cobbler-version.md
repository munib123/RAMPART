# Vulnerability: Cobbler Version Detection
**Classification:** TECH
**Source:** Nuclei Template (`cobbler-version.yaml`)

## Description
Obtain cobbler version information

## Vulnerable Code Pattern / Exploit Payload
```http
POST {{BaseURL}}/cobbler_api
```

