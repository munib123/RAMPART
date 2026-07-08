# Vulnerability: Detect .dockercfg
**Classification:** DOCKER
**Source:** Nuclei Template (`dockercfg-config.yaml`)

## Description
Docker registry authentication data

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.dockercfg
GET {{BaseURL}}/.docker/config.json
```

