# Vulnerability: InterMapper - Exposure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`intermapper-exposure.yaml`)

## Description
Detected unauthenticated InterMapper access, which could allow unauthorized users to view or interact with monitoring data without proper authentication.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

