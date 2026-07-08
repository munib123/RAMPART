# Vulnerability: Alibaba Cloud OSS Bucket - Public Listing Enabled
**Classification:** ALIBABA
**Source:** Nuclei Template (`alibaba-bucket-listing.yaml`)

## Description
Alibaba Cloud Object Storage Service (OSS) bucket is publicly accessible and allows anonymous listing of objects. This misconfiguration can expose sensitive data, lead to data breaches, and result in unexpected charges on the Alibaba Cloud bill.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

