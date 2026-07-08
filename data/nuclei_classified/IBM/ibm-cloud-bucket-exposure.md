# Vulnerability: IBM Cloud Object Storage - Bucket Exposure
**Classification:** IBM
**Source:** Nuclei Template (`ibm-cloud-bucket-exposure.yaml`)

## Description
IBM Cloud Object Storage bucket is publicly accessible, potentially exposing sensitive files and data. Public bucket listing allows enumeration of stored objects.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/?list-type=2
```

