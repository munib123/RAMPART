# Vulnerability: Google Cloud Storage - Public Bucket Listing
**Classification:** EXPOSURE
**Source:** Nuclei Template (`gcs-bucket-listing.yaml`)

## Description
Detected Google Cloud Storage bucket was publicly accessible and allows listing of objects, potentially exposing sensitive files.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

