# Vulnerability: GKE Cluster Not Using Shielded Nodes
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-gke-shielded-nodes-disabled.yaml`)

## Description
Ensure that your Google Kubernetes Engine (GKE) clusters are configured to use Shielded GKE Nodes to protect against rootkits and bootkits. Shielded GKE Nodes provide verifiable node identity and integrity through the use of Secure Boot, virtual trusted platform module (vTPM)-enabled measured boot, and integrity monitoring.

## Secure Mitigation
Enable Shielded GKE Nodes for your clusters using the 'gcloud container clusters update' command with --enable-shielded-nodes flag or through the console. For new clusters, use --enable-shielded-nodes flag during cluster creation.

