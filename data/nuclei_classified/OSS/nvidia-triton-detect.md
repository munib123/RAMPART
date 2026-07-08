# Vulnerability: Triton Inference Server - Detect
**Classification:** OSS
**Source:** Nuclei Template (`nvidia-triton-detect.yaml`)

## Description
Detected the NVIDIA Triton Inference Server, an open-source platform for serving AI/ML models. It supported multiple frameworks and exposed HTTP/gRPC endpoints for high-performance inferencing.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/v2
```

