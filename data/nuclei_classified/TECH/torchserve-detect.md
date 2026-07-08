# Vulnerability: TorchServe API Description - Detect
**Classification:** TECH
**Source:** Nuclei Template (`torchserve-detect.yaml`)

## Description
Detects the presence of TorchServe APIs.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api-description
```

