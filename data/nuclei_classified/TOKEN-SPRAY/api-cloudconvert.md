# Vulnerability: CloudConvert API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-cloudconvert.yaml`)

## Description
Online file converter for audio, video, document, ebook, archive, image, spreadsheet, presentation

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.cloudconvert.com/v2/tasks HTTP/1.1
Host: api.cloudconvert.com
Authorization: Bearer {{token}}
```

