# Vulnerability: Kubelet Running Pods
**Classification:** TECH
**Source:** Nuclei Template (`kubelet-runningpods.yaml`)

## Description
Scans for kubelet running pods

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/runningpods/
```

