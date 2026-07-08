# Vulnerability: GKE Clusters Without Workload Identity Federation
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-gke-workload-identity-disabled.yaml`)

## Description
Ensure that Workload Identity Federation is enabled for your Google Kubernetes Engine (GKE) clusters to securely connect to Google Cloud APIs from Kubernetes workloads. Workload Identity Federation enhances security, simplifies access management, and eliminates the need for less secure methods like service account keys.

## Secure Mitigation
Enable Workload Identity Federation for your GKE clusters using:
gcloud container clusters update CLUSTER_NAME --region=REGION --workload-pool=PROJECT_ID.svc.id.goog

