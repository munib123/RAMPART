# Vulnerability: Image Pull Policy set to Always
**Classification:** CLOUD
**Source:** Nuclei Template (`k8s-image-pull-policy-always.yaml`)

## Description
Ensures that Kubernetes deployments have the image pull policy set to 'Always', which guarantees the most up-to-date version of the image is used.

## Secure Mitigation
Update the image pull policy in Kubernetes Deployments to 'Always' to ensure that the latest container images are always used.

