# Vulnerability: GKE Clusters Without Release Channel Configuration
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-gke-release-channel-disabled.yaml`)

## Description
Ensure that your Google Kubernetes Engine (GKE) clusters are subscribed to either Regular or Stable release channels to automate version management and upgrades. Release channels automatically select cluster versions to provide a balance between new features and stability, while ensuring critical security patches are delivered.

## Secure Mitigation
Configure a release channel for your GKE clusters using:
gcloud container clusters update CLUSTER_NAME --region=REGION --release-channel regular

