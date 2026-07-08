# Vulnerability: Kubelet Healthz
**Classification:** TECH
**Source:** Nuclei Template (`kubelet-healthz.yaml`)

## Description
Scans for kubelet healthz

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/healthz
```

