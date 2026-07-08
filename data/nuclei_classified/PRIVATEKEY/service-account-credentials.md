# Vulnerability: Service Account Credentials File Disclosure
**Classification:** PRIVATEKEY
**Source:** Nuclei Template (`service-account-credentials.yaml`)

## Description
Service Account Credentials internal file is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/assets/other/service-account-credentials.json
GET {{BaseURL}}/service-account-credentials.json
GET {{BaseURL}}/serviceAccountCredentials.json
```

