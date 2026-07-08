# Vulnerability: GKE Clusters Without Binary Authorization Enabled
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-gke-binary-authorization-disabled.yaml`)

## Description
Ensure that Binary Authorization is enabled for your Google Kubernetes Engine (GKE) clusters to enforce container image security policies. Binary Authorization enhances security by ensuring only trusted container images can be deployed, reducing the risk of deploying vulnerable or unauthorized software.

## Secure Mitigation
Enable Binary Authorization for your GKE clusters using:
gcloud container clusters update CLUSTER_NAME --zone=ZONE --binauthz-evaluation-mode=project-singleton-policy-enforce

