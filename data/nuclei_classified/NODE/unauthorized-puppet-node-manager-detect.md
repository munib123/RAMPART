# Vulnerability: Puppet Node Manager - Unauthorized Access
**Classification:** NODE
**Source:** Nuclei Template (`unauthorized-puppet-node-manager-detect.yaml`)

## Description
Pupper Node Manager is exposed to external users.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

