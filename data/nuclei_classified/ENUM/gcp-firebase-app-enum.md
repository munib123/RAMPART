# Vulnerability: GCP Firebase Apps - Cloud Enumeration
**Classification:** ENUM
**Source:** Nuclei Template (`gcp-firebase-app-enum.yaml`)

## Description
Searches for Firebase Apps in GCP.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://{{wordlist}}.{{BaseDNS}} HTTP/1.1
Host: {{wordlist}}.{{BaseDNS}}
```

