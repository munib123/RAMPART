# Vulnerability: Langflow - Detect
**Classification:** TECH
**Source:** Nuclei Template (`langflow-detect.yaml`)

## Description
Langflow was detected. Langflow is an open-source visual LLM flow builder built on LangChain, providing a drag-and-drop interface for building AI pipelines and agents. Exposed instances may allow access to AI workflow configurations and API keys.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api/v1/version
GET {{BaseURL}}
```

