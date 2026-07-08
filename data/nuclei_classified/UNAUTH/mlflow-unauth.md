# Vulnerability: Mlflow - Unauthenticated Access
**Classification:** UNAUTH
**Source:** Nuclei Template (`mlflow-unauth.yaml`)

## Description
Unauthenticated Access to MLflow dashboard.

## Secure Mitigation
Add User Authentication

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/ajax-api/2.0/preview/mlflow/experiments/get?experiment_id=0
```

