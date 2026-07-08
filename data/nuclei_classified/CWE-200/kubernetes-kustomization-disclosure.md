# Vulnerability: Kubernetes Kustomize Configuration - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`kubernetes-kustomization-disclosure.yaml`)

## Description
Kubernetes Kustomize configuration was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/kustomization.yml
```

