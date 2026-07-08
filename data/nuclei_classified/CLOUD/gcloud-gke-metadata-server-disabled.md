# Vulnerability: GKE Clusters Without Metadata Server Enabled
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-gke-metadata-server-disabled.yaml`)

## Description
Ensure that GKE Metadata Server is enabled for your Google Kubernetes Engine (GKE) cluster nodes to enhance security by restricting workload access to sensitive instance information. The GKE Metadata Server feature requires Workload Identity for improved authentication and authorization.

## Secure Mitigation
Enable GKE Metadata Server for your cluster node pools using:
gcloud container node-pools update POOL_NAME --cluster=CLUSTER_NAME --workload-metadata-from-node=GKE_METADATA

