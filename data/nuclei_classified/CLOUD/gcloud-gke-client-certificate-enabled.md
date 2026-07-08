# Vulnerability: GKE Clusters With Client Certificate Authentication Enabled
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-gke-client-certificate-enabled.yaml`)

## Description
Ensure that authentication using client certificates is disabled for your Google Kubernetes Engine (GKE) clusters. Client certificates require manual key rotation for authentication and are difficult to revoke. It is highly recommended to use alternative authentication methods like OpenID Connect, which is the default authentication method used by gcloud and handles token management automatically.

## Secure Mitigation
Re-create your clusters without client certificates using:
gcloud container clusters create NEW_CLUSTER_NAME --no-issue-client-certificate

