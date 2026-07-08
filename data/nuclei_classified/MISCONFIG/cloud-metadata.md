# Vulnerability: GCP/AWS Metadata Disclosure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`cloud-metadata.yaml`)

## Description
GCP/AWS Metadata is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

