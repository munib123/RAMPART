# Vulnerability: Cisco Unified Communications Manager - Cluster Enumeration
**Classification:** CISCO
**Source:** Nuclei Template (`cisco-ucm-cluster-enum.yaml`)

## Description
Enumerated Cisco UCM cluster nodes (servers) using the unauthenticated UDS API (XML), allowing identification of backend servers without authentication.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/cucm-uds/servers
```

