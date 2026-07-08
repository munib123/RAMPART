# Vulnerability: Kube API Nodes
**Classification:** TECH
**Source:** Nuclei Template (`kube-api-nodes.yaml`)

## Description
Scans for kube nodes

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api/v1/nodes
```

