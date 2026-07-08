# Vulnerability: Kubernetes Version Exposure
**Classification:** TECH
**Source:** Nuclei Template (`kubernetes-version.yaml`)

## Description
Searches for exposed Kubernetes API servers which return version information unauthenticated. For Google Kubernetes Engine (GKE) and Amazon Elastic Kubernetes Service (EKS) this template will extract default patch version for you.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/version
```

