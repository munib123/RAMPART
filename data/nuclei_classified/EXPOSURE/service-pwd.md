# Vulnerability: service.pwd - Sensitive Information Disclosure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`service-pwd.yaml`)

## Description
service.pwd was discovered, which is likely to contain sensitive information.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/_vti_pvt/service.pwd
```

