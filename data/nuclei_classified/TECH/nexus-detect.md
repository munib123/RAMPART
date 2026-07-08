# Vulnerability: Nexus Repository Manager (NRM) Instance Detection Template
**Classification:** TECH
**Source:** Nuclei Template (`nexus-detect.yaml`)

## Description
Try to detect the presence of a NRM instance via the REST API OpenDocument descriptor.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/service/rest/swagger.json
```

