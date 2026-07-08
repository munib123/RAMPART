# Vulnerability: LiteLLM Proxy - Model Exposure
**Classification:** CWE-862
**Source:** Nuclei Template (`litellm-unauth-model-exposure.yaml`)

## Description
LiteLLM proxy was detected with anonymous access to the model listing API. LiteLLM proxies that ship without `general_settings.master_key` (or with the key disabled) expose the configured upstream model catalog via /v1/models and /model/info — revealing which OpenAI / Anthropic / Azure / Bedrock / local-LLM endpoints are wired in, often along with their litellm_params routing config, and frequently leaving /chat/completions and /embeddings reachable without any bearer token.

## Secure Mitigation
Set `general_settings.master_key: sk-...` in the LiteLLM config, or pass `--api_key` on startup. Enforce per-user virtual keys via the LiteLLM admin API and place the proxy behind authenticated reverse proxy or service mesh.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/model/info
```

