# Vulnerability: Containers sharing host IPC namespace
**Classification:** CLOUD
**Source:** Nuclei Template (`k8s-containers-share-host-ipc.yaml`)

## Description
Checks if any containers in Kubernetes Pods are configured to share the host's IPC namespace, which can lead to security risks.

## Secure Mitigation
Ensure that no container in Kubernetes Pods is set to share the host IPC namespace. Configure 'spec.hostIPC' to 'false' for all pods to isolate IPC namespaces.

