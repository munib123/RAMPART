# Vulnerability: GCP Buckets - Cloud Enumeration
**Classification:** CLOUD
**Source:** Nuclei Template (`gcp-bucket-enum.yaml`)

## Description
Searches for open and protected buckets in GCP.

## Vulnerable Code Pattern / Exploit Payload
```http
GET http://{{wordlist}}.{{BaseDNS}} HTTP/1.1
Host: {{wordlist}}.{{BaseDNS}}
```

