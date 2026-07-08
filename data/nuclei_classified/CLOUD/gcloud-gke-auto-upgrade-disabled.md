# Vulnerability: GKE Node Pools Without Auto-Upgrade Enabled
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-gke-auto-upgrade-disabled.yaml`)

## Description
Ensure that the Auto-Upgrade feature is enabled for all the nodes running within your Google Kubernetes Engine (GKE) clusters. This feature helps you keep your cluster nodes up to date with the latest supported version of Kubernetes, automatically applying security fixes and new functionalities.

## Secure Mitigation
Enable auto-upgrade for your GKE cluster node pools using:
gcloud container node-pools update POOL_NAME --cluster=CLUSTER_NAME --region=REGION --enable-autoupgrade

