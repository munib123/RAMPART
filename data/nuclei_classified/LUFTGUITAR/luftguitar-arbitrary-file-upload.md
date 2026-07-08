# Vulnerability: Luftguitar CMS Arbitrary File Upload
**Classification:** LUFTGUITAR
**Source:** Nuclei Template (`luftguitar-arbitrary-file-upload.yaml`)

## Description
A vulnerability in Luftguitar CMS allows remote unauthenticated users to upload files to the remote service via the 'ftb.imagegallery.aspx' endpoint.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/ftb.imagegallery.aspx
```

