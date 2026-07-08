# Vulnerability: GKE Clusters Not Using Container-Optimized OS
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-gke-cos-containerd-disabled.yaml`)

## Description
Ensure that your Google Kubernetes Engine (GKE) cluster nodes use the Container-Optimized OS (cos_containerd), a managed, optimized, and hardened base OS provided by GKE to limit the host's attack surface. cos_containerd's layered architecture enables advanced GKE features like gVisor and Image Streaming, and offers improved resource efficiency and security.

## Secure Mitigation
Update your GKE node pools to use Container-Optimized OS with containerd using the command:
gcloud container clusters upgrade CLUSTER_NAME --node-pool POOL_NAME --image-type cos_containerd

