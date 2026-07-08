# Vulnerability: Workload Identity Cluster Creation Not Disabled
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-org-workload-identity.yaml`)

## Description
Ensure that "Disable Workload Identity Cluster Creation" policy is enforced at the GCP organization level in order to require that any new Google Kubernetes Engine (GKE) clusters have the Workload Identity feature disabled at the time of their creation. This constraint policy is useful when you want to tightly control service account access in your organization by disabling Workload Identity in addition to service account creation and service account key creation.

## Secure Mitigation
Enable the "Disable Workload Identity Cluster Creation" policy at the organization level using the 'gcloud alpha resource-manager org-policies enable-enforce' command with the iam.disableWorkloadIdentityClusterCreation constraint.

