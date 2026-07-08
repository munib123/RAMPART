# Vulnerability: Azure Websites - Cloud Enumeration
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-website-enum.yaml`)

## Description
Searches for Azure websites that are registered and responding.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://{{wordlist}}.{{BaseDNS}} HTTP/1.1
Host: {{wordlist}}.{{BaseDNS}}
```

