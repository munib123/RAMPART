# Vulnerability: Kube API Deployments
**Classification:** TECH
**Source:** Nuclei Template (`kube-api-deployments.yaml`)

## Description
Scans for kube deployments

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/apis/apps/v1/namespaces/default/deployments
```

