# Vulnerability: Kubeflow Pipelines Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`kubeflow-pipelines-panel.yaml`)

## Description
Kubeflow Pipelines is an open-source platform for building and deploying portable, scalable ML workflows.
It provides a web UI for managing ML pipelines, experiments, and runs on Kubernetes.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

