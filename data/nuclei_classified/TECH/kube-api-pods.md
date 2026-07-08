# Vulnerability: Kube API Pods
**Classification:** TECH
**Source:** Nuclei Template (`kube-api-pods.yaml`)

## Description
Scans for kube pods

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api/v1/namespaces/default/pods
```

