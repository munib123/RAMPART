# Vulnerability: Razorpay Client ID Disclosure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`razorpay-clientid-disclosure.yaml`)

## Description
Razorpay Client ID is exposed to external users.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

