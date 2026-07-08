# Vulnerability: Feast Feature Store - Detect
**Classification:** TECH
**Source:** Nuclei Template (`feast-detect.yaml`)

## Description
Detected Feast, an open-source feature store for managing and serving ML features.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/p/automl_pipeline
```

