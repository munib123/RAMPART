# Vulnerability: Argilla Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`argilla-panel.yaml`)

## Description
Argilla is an open-source data labelling platform for AI and LLM fine-tuning workflows.
It provides a web interface for annotating datasets used in machine learning model training.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

