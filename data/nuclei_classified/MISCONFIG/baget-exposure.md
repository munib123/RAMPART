# Vulnerability: BaGet - Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`baget-exposure.yaml`)

## Description
BaGet Package Manager is being exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

