# Vulnerability: Cluster Overview - Unauthenticated Dashboard Exposure
**Classification:** CLUSTER
**Source:** Nuclei Template (`cluster-panel.yaml`)

## Description
Cluster Overview dashboard is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
POST {{BaseURL}}/ui/login
```

