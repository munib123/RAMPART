# Vulnerability: Ensure kube-apiserver --anonymous-auth is explicitly disabled
**Classification:** CLOUD
**Source:** Nuclei Template (`k8s-apiserver-anonymous-access.yaml`)

## Description
Checks whether kube-apiserver explicitly sets --anonymous-auth=false in its startup arguments.

## Secure Mitigation
Edit the kube-apiserver manifest (e.g., /etc/kubernetes/manifests/kube-apiserver.yaml) or startup flags
and ensure "--anonymous-auth=false" is present in the apiserver arguments.

