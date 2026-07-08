# Vulnerability: Google Cloud Credentials
**Classification:** GOOGLE
**Source:** Nuclei Template (`gcloud-credentials.yaml`)

## Description
Google Cloud Crdentials file is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/credentials.db
GET {{BaseURL}}/.config/gcloud/credentials.db
```

