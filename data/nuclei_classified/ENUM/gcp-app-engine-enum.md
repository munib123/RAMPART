# Vulnerability: GCP App Engine (Appspot) - Cloud Enumeration
**Classification:** ENUM
**Source:** Nuclei Template (`gcp-app-engine-enum.yaml`)

## Description
Searches for App Engine Apps in GCP.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://{{wordlist}}.{{BaseDNS}} HTTP/1.1
Host: {{wordlist}}.{{BaseDNS}}
```

