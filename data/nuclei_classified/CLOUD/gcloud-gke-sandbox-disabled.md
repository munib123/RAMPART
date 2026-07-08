# Vulnerability: GKE Cluster Not Using Sandbox with gVisor
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-gke-sandbox-disabled.yaml`)

## Description
Ensure that your Google Kubernetes Engine (GKE) clusters are configured to use GKE Sandbox with gVisor to provide an additional layer of security isolation for containers. GKE Sandbox uses gVisor, a container runtime sandbox, to help isolate containers and protect the underlying host kernel.

## Secure Mitigation
Enable GKE Sandbox for your clusters using the 'gcloud container clusters create' command with --sandbox=type=gvisor flag or modify existing node pools to use gVisor sandbox.

