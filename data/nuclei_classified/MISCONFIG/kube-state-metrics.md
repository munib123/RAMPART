# Vulnerability: Kube State Metrics Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`kube-state-metrics.yaml`)

## Description
An attacker can detect the public instance of a Kube-State-Metrics metrics. The Kubernetes API server exposes data about the count, health, and availability of pods, nodes, and other Kubernetes objects.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/metrics
```

