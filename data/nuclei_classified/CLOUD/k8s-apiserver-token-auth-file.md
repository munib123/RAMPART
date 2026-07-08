# Vulnerability: Detect kube-apiserver --token-auth-file usage
**Classification:** CLOUD
**Source:** Nuclei Template (`k8s-apiserver-token-auth-file.yaml`)

## Description
Detects whether kube-apiserver includes the --token-auth-file startup argument.

## Secure Mitigation
Remove the --token-auth-file argument from the kube-apiserver startup flags (e.g., edit
/etc/kubernetes/manifests/kube-apiserver.yaml) or ensure any tokens in that file are rotated
and managed securely. Prefer dynamic, short-lived service account tokens and RBAC.

