# Vulnerability: ClusterRoles with Risky nodes/proxy GET Permission
**Classification:** CLOUD
**Source:** Nuclei Template (`k8s-clusterrole-nodes-proxy-rce.yaml`)

## Description
Detects Kubernetes ClusterRoles that grant GET permission on nodes/proxy resource.
Due to an authorization inconsistency in Kubelet, the nodes/proxy GET permission allows
execution of commands in any container via WebSocket connections to the Kubelet API.
The Kubelet authorizes based on the initial HTTP GET method of WebSocket handshake
rather than the actual operation (exec/run/attach) which should require CREATE permission.

## Secure Mitigation
Remove nodes/proxy GET permissions from ClusterRoles unless absolutely necessary.
Restrict network access to Kubelet port 10250 and implement network policies.

