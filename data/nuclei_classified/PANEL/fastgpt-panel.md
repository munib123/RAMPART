# Vulnerability: FastGPT Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`fastgpt-panel.yaml`)

## Description
FastGPT is a knowledge-based platform built on the LLM, offering out-of-the-box
data processing and model invocation capabilities.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

