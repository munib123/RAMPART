# Vulnerability: SAP Directory Listing
**Classification:** SAP
**Source:** Nuclei Template (`sap-directory-listing.yaml`)

## Description
SAP Directory Listing is enabled.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/irj/go/km/navigation/
```

