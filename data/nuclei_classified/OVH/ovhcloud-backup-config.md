# Vulnerability: OVHcloud Backup Configuration - Exposure
**Classification:** OVH
**Source:** Nuclei Template (`ovhcloud-backup-config.yaml`)

## Description
Detected exposed OVHcloud backup configuration files (ovh-backups.json) containing sensitive credentials such as OpenStack/Swift authentication details, API keys, and storage configuration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/ovh-backups.json
GET {{BaseURL}}/config/ovh-backups.json
GET {{BaseURL}}/backup/ovh-backups.json
GET {{BaseURL}}/storage/ovh-backups.json
```

