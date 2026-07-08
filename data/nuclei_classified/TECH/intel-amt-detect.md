# Vulnerability: Intel Active Management Technology Server Detection
**Classification:** TECH
**Source:** Nuclei Template (`intel-amt-detect.yaml`)

## Description
Detected Intel Active Management Technology (AMT) web interfaces by identifying the Server header in HTTP responses.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/
```

