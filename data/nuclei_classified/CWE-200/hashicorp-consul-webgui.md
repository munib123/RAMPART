# Vulnerability: HashiCorp Consul Web UI Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`hashicorp-consul-webgui.yaml`)

## Description
HashiCorp Consul Web UI login panel was detected,

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/ui/
```

