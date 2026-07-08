# Vulnerability: llama.cpp - Detect
**Classification:** TECH
**Source:** Nuclei Template (`llamacpp-detect.yaml`)

## Description
Detected llama.cpp, a lightweight C/C++ inference engine for running GGUF-format large language models locally. Exposed instances serve an OpenAI-compatible REST API and a built-in web chat interface with no authentication by default.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /health HTTP/1.1
Host: {{Hostname}}
```

