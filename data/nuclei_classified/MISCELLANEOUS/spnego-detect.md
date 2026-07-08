# Vulnerability: SPNEGO - Detect
**Classification:** MISCELLANEOUS
**Source:** Nuclei Template (`spnego-detect.yaml`)

## Description
SPNEGO stands for Simple and Protected GSSAPI Negotiation Mechanism. It is a protocol used for secure authentication and negotiation between client and server applications in a network environment. SPNEGO is based on the Generic Security Services Application Programming Interface (GSSAPI) framework.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

