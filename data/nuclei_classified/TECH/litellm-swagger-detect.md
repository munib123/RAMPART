# Vulnerability: LiteLLM API - Swagger UI Detection
**Classification:** TECH
**Source:** Nuclei Template (`litellm-swagger-detect.yaml`)

## Description
Detects exposed LiteLLM API Swagger UI interface. LiteLLM is a unified API for 100+ LLM providers (OpenAI, Azure, Anthropic, etc.).

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

