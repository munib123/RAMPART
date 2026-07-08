# Vulnerability: Adobe ColdFusion Detector
**Classification:** ADOBE
**Source:** Nuclei Template (`adobe-coldfusion-detect.yaml`)

## Description
With this template we can detect the version number of Coldfusion instances based on their logos.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/CFIDE/administrator/images/mx_login.gif
GET {{BaseURL}}/cfide/administrator/images/mx_login.gif
GET {{BaseURL}}/CFIDE/administrator/images/background.jpg
GET {{BaseURL}}/cfide/administrator/images/background.jpg
GET {{BaseURL}}/CFIDE/administrator/images/componentutilslogin.jpg
GET {{BaseURL}}/cfide/administrator/images/componentutilslogin.jpg
```

