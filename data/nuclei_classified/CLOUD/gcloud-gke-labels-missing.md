# Vulnerability: GKE Clusters Missing Resource Labels
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-gke-labels-missing.yaml`)

## Description
Ensure that user-defined labels are being used to tag, collect, and organize GKE clusters within your Google Cloud Platform (GCP) projects. User-defined labels are a lightweight and efficient way to group together related or associated cloud resources. These are unrelated to Kubernetes labels.

## Secure Mitigation
Add user-defined labels to your GKE clusters using the 'gcloud container clusters update' command with --update-labels flag or through the Google Cloud Console. Use meaningful labels like environment, team, billing, version, or owner.

