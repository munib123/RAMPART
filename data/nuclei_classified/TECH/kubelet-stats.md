# Vulnerability: Kubelet Stats
**Classification:** TECH
**Source:** Nuclei Template (`kubelet-stats.yaml`)

## Description
Scans for kubelet stats

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/stats/summary
```

