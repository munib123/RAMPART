# Vulnerability: Etcd Server - Unauthenticated Access
**Classification:** TECH
**Source:** Nuclei Template (`unauth-etcd-server.yaml`)

## Description
A Kubernetes etcd server stores the cluster secrets and configurations files. Anonymous access on etcd allows unauthenticated access the data without providing any authentication credentials.

## Secure Mitigation
https://etcd.io/docs/v2.3/authentication

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/v2/keys/
```

