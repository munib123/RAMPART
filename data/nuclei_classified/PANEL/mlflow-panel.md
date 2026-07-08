# Vulnerability: MLflow Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`mlflow-panel.yaml`)

## Description
MLflow is an open-source platform for managing the end-to-end machine learning
lifecycle including experimentation, reproducibility, and deployment. This template
detects exposed MLflow tracking server UI instances.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

