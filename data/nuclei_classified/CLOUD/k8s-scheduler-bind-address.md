# Vulnerability: Ensure kube-scheduler --bind-address is set to localhost
**Classification:** CLOUD
**Source:** Nuclei Template (`k8s-scheduler-bind-address.yaml`)

## Description
Ensure kube-scheduler is bound to localhost (127.0.0.1 or ::1). If --bind-address is missing or set to
0.0.0.0 (::), the scheduler API may be reachable from all network interfaces, increasing exposure of the
control-plane component.

## Secure Mitigation
Set --bind-address=127.0.0.1 (or ::1) in the kube-scheduler startup arguments. For example, edit
/etc/kubernetes/manifests/kube-scheduler.yaml and add the argument to the command section.

