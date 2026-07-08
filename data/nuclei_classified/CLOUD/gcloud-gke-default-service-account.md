# Vulnerability: GKE Clusters Using Default Service Account
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-gke-default-service-account.yaml`)

## Description
Ensure that your Google Kubernetes Engine (GKE) clusters are configured to use user-managed service accounts instead of the default service account managed by Google Cloud. The default service account has broad permissions across your GCP project, which violates the Principle of Least Privilege (POLP).

## Secure Mitigation
Create a custom service account with minimal required permissions and update your node pools to use it instead of the default service account.

