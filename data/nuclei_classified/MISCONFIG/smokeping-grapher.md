# Vulnerability: SmokePing Latency Page for Network Latency Grapher
**Classification:** MISCONFIG
**Source:** Nuclei Template (`smokeping-grapher.yaml`)

## Description
SmokePing Latency Page is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/smokeping/
```

