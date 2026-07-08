# Vulnerability: Manage Engine AD Search
**Classification:** UNAUTH
**Source:** Nuclei Template (`manage-engine-ad-search.yaml`)

## Description
Manage Engine AD Manager service can be configured to allow anonymous users to browse the AD list remotely.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/ADSearch.cc?methodToCall=search
```

