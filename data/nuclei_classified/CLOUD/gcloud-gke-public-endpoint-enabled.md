# Vulnerability: GKE Clusters with Public Control Plane Endpoints
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-gke-public-endpoint-enabled.yaml`)

## Description
Ensure that your Google Kubernetes Engine (GKE) clusters are configured to use private endpoints only for control plane access, effectively disabling external access to the Kubernetes API. This requires configuring the GKE cluster with private nodes, a private master IP range, and IP aliasing.

