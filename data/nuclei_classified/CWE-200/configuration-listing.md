# Vulnerability: Sensitive Configuration Files Listing - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`configuration-listing.yaml`)

## Description
Listing of sensitive configuration files containing items such as usernames, passwords, and IP addresses was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/config/
```

