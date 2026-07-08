# Vulnerability: Headlamp Kubernetes UI Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`headlamp-panel.yaml`)

## Description
Detected Headlamp Kubernetes Web UI panel exposed, which could lead to unauthorized access to Kubernetes cluster management if not properly secured.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/settings/plugins
GET {{BaseURL}}/settings/cluster
```

