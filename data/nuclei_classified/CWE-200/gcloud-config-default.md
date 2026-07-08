# Vulnerability: Google Cloud Default Config - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`gcloud-config-default.yaml`)

## Description
Google Cloud default configuration was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/configurations/config_default
GET {{BaseURL}}/.config/gcloud/configurations/config_default
```

