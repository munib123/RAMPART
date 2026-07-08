# Vulnerability: KubeCost - Unauthenticated Dashboard Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`unauth-kubecost.yaml`)

## Description
KubeCost Dashboard is exposed to external users.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/overview.html
```

