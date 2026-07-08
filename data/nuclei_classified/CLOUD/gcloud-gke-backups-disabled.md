# Vulnerability: GKE Clusters Without Backups Enabled
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-gke-backups-disabled.yaml`)

## Description
Ensure that backups are enabled for your Google Kubernetes Engine (GKE) clusters to protect your workloads and enable disaster recovery capabilities. GKE backups capture both configuration and volume data, allowing selective or comprehensive restoration of workloads, which is valuable for disaster recovery, CI/CD pipelines, workload cloning, and managing upgrades.

## Secure Mitigation
Enable backups for your GKE clusters using:
gcloud container clusters update CLUSTER_NAME --region=REGION --update-addons=BackupRestore=ENABLED

