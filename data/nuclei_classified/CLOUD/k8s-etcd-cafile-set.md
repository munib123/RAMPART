# Vulnerability: Ensure etcd-cafile argument set
**Classification:** CLOUD
**Source:** Nuclei Template (`k8s-etcd-cafile-set.yaml`)

## Description
Checks if the etcd-cafile argument is properly set in the etcd configuration, crucial for secure client connections to etcd.

## Secure Mitigation
Configure etcd to use an etcd-cafile argument that points to a valid CA certificate bundle. This setting should be part of the etcd startup arguments or in its configuration file.

