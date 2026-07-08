# Vulnerability: GKE Clusters Without Inter-Node Transparent Encryption
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-gke-transparent-encryption-disabled.yaml`)

## Description
Ensure that encryption of in-transit data for Pod communications across Google Kubernetes Engine (GKE) cluster nodes is enabled with Customer-Managed Encryption Keys (CMEKs). This feature, which requires GKE Dataplane V2, provides additional encryption on top of the default VM NIC-level encryption using WireGuard.

## Secure Mitigation
Enable inter-node transparent encryption for your GKE clusters using:
gcloud container clusters update CLUSTER_NAME --region=REGION --in-transit-encryption inter-node-transparent

