# Vulnerability: Weights & Biases - Detect
**Classification:** TECH
**Source:** Nuclei Template (`weights-biases-detect.yaml`)

## Description
Weights & Biases (W&B) instance was detected. W&B is a popular MLOps platform for experiment tracking, model versioning, and collaborative ML development. Self-hosted deployments expose the full experiment management interface.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

