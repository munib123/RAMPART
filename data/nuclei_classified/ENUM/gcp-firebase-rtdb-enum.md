# Vulnerability: GCP Firebase Realtime Database - Cloud Enumeration
**Classification:** ENUM
**Source:** Nuclei Template (`gcp-firebase-rtdb-enum.yaml`)

## Description
Searches for Firebase Realtime Databases in GCP.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://{{wordlist}}.{{BaseDNS}}/.json HTTP/1.1
Host: {{wordlist}}.{{BaseDNS}}
```

