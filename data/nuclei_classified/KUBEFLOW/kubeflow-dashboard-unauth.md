# Vulnerability: Kubeflow Unauth
**Classification:** KUBEFLOW
**Source:** Nuclei Template (`kubeflow-dashboard-unauth.yaml`)

## Description
Kubeflow internal data is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/pipeline/apis/v1beta1/runs?page_size=5&sort_by=created_at%20desc
```

