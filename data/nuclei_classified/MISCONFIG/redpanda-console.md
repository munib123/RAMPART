# Vulnerability: Redpanda Console - Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`redpanda-console.yaml`)

## Description
Unauthorized access to the Redpanda Console could allow attackers to view or manipulate streaming data, monitor clusters, or access configuration information, leading to potential data leaks or service disruption.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/overview
```

