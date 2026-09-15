# Nuclei Template: LiteLLM Proxy - Model Exposure
**Template ID:** litellm-unauth-model-exposure
**Vulnerability Class:** Missing Authorization
**Severity:** Medium
**CWE:** CWE-862
**Source:** Nuclei Template (`litellm-unauth-model-exposure.yaml`)

## Vulnerability Information & PoC

## Description
LiteLLM proxy was detected with anonymous access to the model listing API. LiteLLM proxies that ship without `general_settings.master_key` (or with the key disabled) expose the configured upstream model catalog via /v1/models and /model/info — revealing which OpenAI / Anthropic / Azure / Bedrock / local-LLM endpoints are wired in, often along with their litellm_params routing config, and frequently leaving /chat/completions and /embeddings reachable without any bearer token.

## Impact
Attackers can enumerate the proxy's full model catalog and abuse the upstream accounts for free inference (cost amplification), exfiltrate any prompt logs cached locally, or pivot to internal-only model endpoints exposed via the proxy's routing config.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/model/info
```

## Remediation
Set `general_settings.master_key: sk-...` in the LiteLLM config, or pass `--api_key` on startup. Enforce per-user virtual keys via the LiteLLM admin API and place the proxy behind authenticated reverse proxy or service mesh.

## References
- https://docs.litellm.ai/docs/proxy/virtual_keys
- https://docs.litellm.ai/docs/proxy/configs
- https://github.com/BerriAI/litellm
