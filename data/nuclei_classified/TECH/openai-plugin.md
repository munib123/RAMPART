# Vulnerability: OpenAI Plugin Detection
**Classification:** TECH
**Source:** Nuclei Template (`openai-plugin.yaml`)

## Description
OpenAI plugins connect ChatGPT to third-party applications. These plugins enable ChatGPT to interact with APIs defined by developers, enhancing ChatGPT's capabilities and allowing it to perform a wide range of actions.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.well-known/ai-plugin.json
```

