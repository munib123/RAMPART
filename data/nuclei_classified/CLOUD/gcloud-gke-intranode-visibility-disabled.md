# Vulnerability: GKE Clusters Without Intranode Visibility Enabled
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-gke-intranode-visibility-disabled.yaml`)

## Description
Ensure that intranode visibility is enabled for your Google Kubernetes Engine (GKE) clusters. This allows you to monitor and troubleshoot network traffic between pods running on the same node, enhancing both visibility and security. When enabled, packets exchanged between Pods are always processed by the VPC network.

## Secure Mitigation
Enable intranode visibility for your GKE clusters using:
gcloud container clusters update CLUSTER_NAME --region=REGION --enable-intra-node-visibility

