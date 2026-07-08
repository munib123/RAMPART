# Vulnerability: Kubelet Metrics
**Classification:** TECH
**Source:** Nuclei Template (`kubelet-metrics.yaml`)

## Description
Kube Metrics Server was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/
GET {{BaseURL}}/metrics
```

