# Nuclei Template: Sensitive Configuration Files Listing - Detect
**Template ID:** configuration-listing
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`configuration-listing.yaml`)

## Vulnerability Information & PoC

## Description
Listing of sensitive configuration files containing items such as usernames, passwords, and IP addresses was detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/config/
```

## References
- https://www.exploit-db.com/ghdb/7014
