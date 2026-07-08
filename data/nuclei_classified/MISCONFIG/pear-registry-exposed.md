# Vulnerability: PEAR Registry Files Exposed
**Classification:** MISCONFIG
**Source:** Nuclei Template (`pear-registry-exposed.yaml`)

## Description
Detected exposed PEAR registry files (.reg) containing serialized PHP metadata, including package versions and local paths. This exposure facilitated supply-chain reconnaissance by revealing installed dependencies and system mappings.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.registry/pear.reg.ber
GET {{BaseURL}}/.registry/pear.reg
GET {{BaseURL}}/PEAR/.registry/pear.reg.ber
GET {{BaseURL}}/PEAR/.registry/pear.reg
```

