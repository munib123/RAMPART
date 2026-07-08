# Vulnerability: OpenMetadata - Detect
**Classification:** TECH
**Source:** Nuclei Template (`openmetadata-detect.yaml`)

## Description
Detects a OpenMetadata server, a unified metadata platform for data discovery, data observability, and data governance powered by a central metadata repository, in-depth column level lineage, and seamless team collaboration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

