# Vulnerability: Ensure kube-controller-manager --bind-address is set to localhost
**Classification:** CLOUD
**Source:** Nuclei Template (`k8s-controller-manager-bind-address.yaml`)

## Description
Ensure kube-controller-manager is bound to localhost (127.0.0.1 or ::1). If --bind-address is missing or
set to 0.0.0.0 (::), the controller-manager API may be reachable from all network interfaces, increasing
exposure of the control-plane component.

## Secure Mitigation
Set --bind-address=127.0.0.1 (or ::1) in the kube-controller-manager startup arguments. For example, edit
/etc/kubernetes/manifests/kube-controller-manager.yaml and add the argument to the command section.

