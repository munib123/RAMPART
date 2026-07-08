# Vulnerability: CARESTREAM Vue Motion Detector
**Classification:** TECH
**Source:** Nuclei Template (`carestream-vue-detect.yaml`)

## Description
This template will detect a running CARESTREAM Vue Motion instance

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/portal/favicon.ico
GET {{BaseURL}}/portal/images/MyVue/MyVueHelp.png
```

