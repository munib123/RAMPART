# Vulnerability: GKE Clusters Without Application-Layer Secrets Encryption
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-gke-secrets-encryption-disabled.yaml`)

## Description
Ensure that encryption of Kubernetes secrets with Customer-Managed Keys (CMKs) is enabled for your Google Kubernetes Engine (GKE) clusters. Application-layer secrets encryption protects your Kubernetes secrets in etcd with an encryption key managed using the Cloud KMS service, providing an additional layer of security for sensitive data.

## Secure Mitigation
Enable application-layer secrets encryption for your GKE clusters using Cloud KMS Customer-Managed Keys (CMKs):
gcloud container clusters update CLUSTER_NAME --database-encryption-key=projects/PROJECT_ID/locations/LOCATION/keyRings/KEYRING/cryptoKeys/KEY

