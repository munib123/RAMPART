# Vulnerability: Kubernetes Pods - API Discovery & Remote Code Execution
**Classification:** K8
**Source:** Nuclei Template (`kubernetes-pods-api.yaml`)

## Description
A Kubernetes Pods API was discovered. When the service port is available, unauthenticated users can execute commands inside the container.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/pods
GET {{BaseURL}}/api/v1/pods
```

