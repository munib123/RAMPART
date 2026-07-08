# Vulnerability: Sensitive Storage Data - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`sensitive-storage-exposure.yaml`)

## Description
A generic search for 'storage' in sensitive key files, file names, logs, etc., returned a match.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/storage/
GET {{BaseURL}}/api_smartapp/storage/
GET {{BaseURL}}/equipbid/storage/
GET {{BaseURL}}/server/storage/
GET {{BaseURL}}/intikal/storage/
GET {{BaseURL}}/elocker_old/storage/
```

