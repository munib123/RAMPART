# Vulnerability: BentoML Prediction Service - Detection
**Classification:** TECH
**Source:** Nuclei Template (`bentoml-detect.yaml`)

## Description
Detected BentoML Prediction Service interface. BentoML was a platform for building, shipping, and scaling AI applications with any ML framework.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

