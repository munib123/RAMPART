# Vulnerability: Apache YARN ResourceManager Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`yarn-manager-exposure.yaml`)

## Description
Apache YARN ResourceManager panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/cluster/cluster
```

