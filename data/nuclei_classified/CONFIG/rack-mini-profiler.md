# Vulnerability: rack-mini-profiler - Environment Information Disclosure
**Classification:** CONFIG
**Source:** Nuclei Template (`rack-mini-profiler.yaml`)

## Description
rack-mini-profiler is prone to environmental information disclosure which could help an attacker formulate additional attacks.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/?pp=env
```

