# Vulnerability: Zimbra Detect
**Classification:** TECH
**Source:** Nuclei Template (`zimbra-detect.yaml`)

## Description
Send a GET request to js file on Zimbra server to obtain version information

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/js/zimbraMail/share/model/ZmSettings.js
```

