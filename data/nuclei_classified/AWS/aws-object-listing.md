# Vulnerability: AWS bucket with Object listing
**Classification:** AWS
**Source:** Nuclei Template (`aws-object-listing.yaml`)

## Description
Object listing is enabled in AWS bucket.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

