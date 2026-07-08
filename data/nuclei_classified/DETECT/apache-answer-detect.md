# Vulnerability: Apache Answer - Detection
**Classification:** DETECT
**Source:** Nuclei Template (`apache-answer-detect.yaml`)

## Description
Detects Apache Answer version through API endpoit

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/answer/api/v1/siteinfo
```

