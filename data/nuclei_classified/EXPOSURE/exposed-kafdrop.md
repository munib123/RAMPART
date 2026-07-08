# Vulnerability: Publicly exposed Kafdrop Interface
**Classification:** EXPOSURE
**Source:** Nuclei Template (`exposed-kafdrop.yaml`)

## Description
Publicly Kafdrop Interface is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

