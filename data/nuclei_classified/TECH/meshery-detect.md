# Vulnerability: Meshery - Detect
**Classification:** TECH
**Source:** Nuclei Template (`meshery-detect.yaml`)

## Description
Meshery is a open source, cloud native manager that enables the design and management of all Kubernetes-based infrastructure and applications (multi-cloud).

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api/providers
```

