# Vulnerability: LVS Lean Value Management System Business - Directory Listing
**Classification:** LEAN-VALUE
**Source:** Nuclei Template (`lean-value-listing.yaml`)

## Description
Multiple systems of Hangzhou Jila Technology Co., Ltd. have been found to have directory traversal vulnerabilities. These vulnerabilities arise from the inadequate access controls implemented in the /Business/ directory. Malicious actors can potentially leverage these vulnerabilities to illicitly access sensitive information.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/Business/
```

