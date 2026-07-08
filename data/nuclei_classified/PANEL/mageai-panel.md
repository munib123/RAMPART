# Vulnerability: Mage AI Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`mageai-panel.yaml`)

## Description
Mage AI (mage.ai / github.com/mage-ai/mage-ai) is an open-source data pipeline + orchestration platform with a notebook-style UI. Self-hosted instances default to TCP 6789 and historically have shipped without authentication. Exposed instances may reveal pipeline source, secrets, and provide an authenticated path to arbitrary code execution via custom blocks.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/api/status
```

