# Vulnerability: Cisco Smart Software Manager On-Prem Panel - Detect
**Classification:** CISCO
**Source:** Nuclei Template (`cisco-onprem-panel.yaml`)

## Description
Cisco Smart Software Manager On-Prem is an on-premises software license management solution offered by Cisco. It enables organizations to manage and optimize their Cisco software licenses, entitlements, and usage in their local data centers, providing greater control and visibility over software assets.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/#/logIn?redirectURL=%2F
```

