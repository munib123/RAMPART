# Vulnerability: GKE Clusters Without Private Nodes Enabled
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-gke-private-nodes-disabled.yaml`)

## Description
Ensure that your Google Kubernetes Engine (GKE) clusters are configured to provision all nodes with only internal IP addresses (private nodes). This prevents external clients from accessing the nodes and prevents the nodes from having direct access to the Internet, reducing the attack surface.

## Secure Mitigation
Enable private nodes for your GKE clusters using:
gcloud container clusters update CLUSTER_NAME --enable-private-nodes --enable-ip-alias

