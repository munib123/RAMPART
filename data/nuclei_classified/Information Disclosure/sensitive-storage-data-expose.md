# Nuclei Template: Sensitive Storage Data - Detect
**Template ID:** sensitive-storage-data-expose
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`sensitive-storage-exposure.yaml`)

## Vulnerability Information & PoC

## Description
A generic search for 'storage' in sensitive key files, file names, logs, etc., returned a match.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/storage/
GET {{BaseURL}}/api_smartapp/storage/
GET {{BaseURL}}/equipbid/storage/
GET {{BaseURL}}/server/storage/
GET {{BaseURL}}/intikal/storage/
GET {{BaseURL}}/elocker_old/storage/
```

## References
- https://www.exploit-db.com/ghdb/6304
