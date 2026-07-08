# Vulnerability: AWS X-Ray Sample Application
**Classification:** MISCONFIG
**Source:** Nuclei Template (`aws-xray-application.yaml`)

## Description
AWS X-Ray is a service that helps developers analyze and debug distributed applications.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

