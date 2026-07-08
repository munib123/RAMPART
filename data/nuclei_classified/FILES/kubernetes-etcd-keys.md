# Vulnerability: Kubernetes etcd Keys - Exposure
**Classification:** FILES
**Source:** Nuclei Template (`kubernetes-etcd-keys.yaml`)

## Description
Kubernetes private etcd keys are exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/apiserver-etcd-client.key
```

