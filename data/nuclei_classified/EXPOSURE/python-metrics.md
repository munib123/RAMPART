# Vulnerability: Detect Python Exposed Metrics
**Classification:** EXPOSURE
**Source:** Nuclei Template (`python-metrics.yaml`)

## Description
Information Disclosure of Garbage Collection

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/metrics
```

