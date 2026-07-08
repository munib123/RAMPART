# Vulnerability: Azure Pipelines Configuration File Disclosure
**Classification:** CONFIG
**Source:** Nuclei Template (`azure-pipelines-exposed.yaml`)

## Description
Azure Pipelines internal critical file is disclosed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.azure-pipelines.yml
GET {{BaseURL}}/azure-pipelines.yml
```

