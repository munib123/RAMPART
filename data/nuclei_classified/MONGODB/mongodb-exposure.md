# Vulnerability: MongoDB Exposure
**Classification:** MONGODB
**Source:** Nuclei Template (`mongodb-exposure.yaml`)

## Description
Detected MongoDB instances exposed over HTTP using the native driver port.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

