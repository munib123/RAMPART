# Vulnerability: Ensure etcd cert and key set
**Classification:** CLOUD
**Source:** Nuclei Template (`k8s-etcd-files-set.yaml`)

## Description
Checks if the etcd-certfile and etcd-keyfile arguments are properly set in the etcd server configuration, crucial for secure communication.

## Secure Mitigation
Configure the etcd server to use etcd-certfile and etcd-keyfile arguments that point to valid certificate and key files respectively. This ensures that communications to and from the etcd server are properly encrypted.

