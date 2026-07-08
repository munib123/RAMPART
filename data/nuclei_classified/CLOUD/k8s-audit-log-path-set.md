# Vulnerability: Ensure audit-log-path set
**Classification:** CLOUD
**Source:** Nuclei Template (`k8s-audit-log-path-set.yaml`)

## Description
Checks if the audit-log-path argument is properly set in the Kubernetes API server configuration, which is essential for maintaining a reliable audit trail.

## Secure Mitigation
Configure the Kubernetes API server to include the audit-log-path argument pointing to a secure, writeable directory where audit logs will be stored. Ensure that this directory is properly secured and regularly monitored.

