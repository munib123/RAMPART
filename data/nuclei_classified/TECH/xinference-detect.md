# Vulnerability: Xinference - Detect
**Classification:** TECH
**Source:** Nuclei Template (`xinference-detect.yaml`)

## Description
Xinference (Xorbits Inference) was detected. Xinference is a distributed LLM inference framework supporting multiple model types including LLMs, embeddings, and multimodal models. The API endpoint exposes an OpenAI-compatible interface with model information.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /v1/models HTTP/1.1
Host: {{Hostname}}
```

