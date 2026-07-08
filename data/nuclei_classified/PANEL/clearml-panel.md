# Vulnerability: ClearML Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`clearml-panel.yaml`)

## Description
ClearML was detected. ClearML is an open-source MLOps platform for experiment tracking, model management, and pipeline orchestration. Exposed instances may allow access to ML experiments, models, and infrastructure configurations.

## Vulnerable Code Pattern / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}
```

