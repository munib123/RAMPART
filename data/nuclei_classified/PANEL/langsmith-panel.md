# Vulnerability: LangSmith Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`langsmith-panel.yaml`)

## Description
LangSmith panel was detected. LangSmith is LangChain's platform for debugging, testing, evaluating, and monitoring LLM applications.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

