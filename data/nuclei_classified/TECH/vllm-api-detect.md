# Vulnerability: vLLM OpenAI-Compatible Server - Detect
**Classification:** TECH
**Source:** Nuclei Template (`vllm-api-detect.yaml`)

## Description
Detected vLLM was a high-throughput LLM serving engine that exposed an OpenAI-compatible HTTP API on TCP 8000 with no authentication by default.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

