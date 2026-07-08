# Vulnerability: Detect Kubernetes Exposed Metrics
**Classification:** KUBERNETES
**Source:** Nuclei Template (`kubernetes-metrics.yaml`)

## Description
Information Disclosure of Garbage Collection

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/metrics
```

