# Vulnerability: Pods with read-only root filesystem
**Classification:** CLOUD
**Source:** Nuclei Template (`k8s-readonly-rootfs.yaml`)

## Description
Checks for pods and containers running with a read-only root filesystem to prevent modifications to the filesystem, enhancing security.

## Secure Mitigation
Configure all pods and containers to have their root filesystem set to read-only mode. This can be achieved by setting the securityContext.readOnlyRootFilesystem parameter to true in the pod or container configuration.

