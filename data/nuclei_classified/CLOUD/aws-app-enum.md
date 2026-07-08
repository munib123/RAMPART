# Vulnerability: AWS Apps - Cloud Enumeration
**Classification:** CLOUD
**Source:** Nuclei Template (`aws-app-enum.yaml`)

## Description
Searches for AWS apps (WorkDocs, WorkMail, Connect, etc.)

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://{{wordlist}}.{{BaseDNS}} HTTP/1.1
Host: {{wordlist}}.{{BaseDNS}}
```

