# Vulnerability: AWS S3 Buckets - Cloud Enumeration
**Classification:** CLOUD
**Source:** Nuclei Template (`aws-s3-bucket-enum.yaml`)

## Description
Searches for open and protected buckets in AWS S3

## Vulnerable Code Pattern / Exploit Payload
```http
GET http://{{wordlist}}.{{BaseDNS}} HTTP/1.1
Host: {{wordlist}}.{{BaseDNS}}
```

