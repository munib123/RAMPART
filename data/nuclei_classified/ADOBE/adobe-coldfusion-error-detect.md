# Vulnerability: Adobe ColdFusion Detector
**Classification:** ADOBE
**Source:** Nuclei Template (`adobe-coldfusion-error-detect.yaml`)

## Description
With this template we can detect a running ColdFusion instance due to an error page.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/_something_.cfm
```

