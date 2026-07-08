# Vulnerability: Hashicorp Consul API Unauthenticated
**Classification:** HASHICORP
**Source:** Nuclei Template (`hashicorp-consul-unauth.yaml`)

## Description
In HashiCorp Consul's API without authentication arises when Consul is improperly secured, exposing its endpoints to unauthorized access.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/v1/health/service/consul
```

