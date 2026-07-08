# Vulnerability: Hashicorp Consul Agent - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`hashicorp-consul-agent.yaml`)

## Description
Hashicorp Consul Agent was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/v1/agent/self
```

