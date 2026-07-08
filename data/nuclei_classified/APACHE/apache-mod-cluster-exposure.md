# Vulnerability: Apache `mod_proxy_cluster` Cluster Manager Interface - Exposure
**Classification:** APACHE
**Source:** Nuclei Template (`apache-mod-cluster-exposure.yaml`)

## Description
The Apache mod_proxy_cluster management interface provides administrative control and visibility into the load balancer’s nodes and contexts.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/mcm
GET {{BaseURL}}/cluster-manager
GET {{BaseURL}}/mod_cluster_manager
```

