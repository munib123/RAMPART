# Vulnerability: GKE Clusters Not Using Confidential Nodes
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-gke-confidential-nodes-disabled.yaml`)

## Description
Ensure that your Google Kubernetes Engine (GKE) cluster node pools use confidential GKE nodes to encrypt all running workloads. Confidential GKE nodes employ hardware-based memory encryption to safeguard your data and applications from unauthorized access or modification while in use.

## Secure Mitigation
Enable confidential GKE nodes for your cluster node pools using:
gcloud container node-pools update POOL_NAME --cluster=CLUSTER_NAME --region=REGION --enable-confidential-nodes

