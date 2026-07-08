# Vulnerability: Google Service Json
**Classification:** GOOGLE
**Source:** Nuclei Template (`google-services-json.yaml`)

## Description
google-services.json internal file is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/google-services.json
GET {{BaseURL}}/app/google-services.json
GET {{BaseURL}}/android/app/google-services.json
```

