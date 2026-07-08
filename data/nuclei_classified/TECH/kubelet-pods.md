# Vulnerability: Kubelet Scan
**Classification:** TECH
**Source:** Nuclei Template (`kubelet-pods.yaml`)

## Description
Scans for kubelet pods

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/pods
```

