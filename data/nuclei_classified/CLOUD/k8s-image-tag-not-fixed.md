# Vulnerability: Image Tag should be fixed - not latest or blank
**Classification:** CLOUD
**Source:** Nuclei Template (`k8s-image-tag-not-fixed.yaml`)

## Description
Checks if Kubernetes Deployment container images are using tags other than 'latest' or blank, which can lead to unstable and unpredictable deployments.

## Secure Mitigation
Use specific image tags for all containers in Kubernetes Deployments to ensure reproducibility and stability of application deployments.

