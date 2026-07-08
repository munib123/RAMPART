# Vulnerability: GKE Node Pools Without Auto-Repair Enabled
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-gke-auto-repair-disabled.yaml`)

## Description
Ensure that the Auto-Repair feature is enabled for all your GKE cluster nodes to help maintain node health. Google Kubernetes Engine (GKE) triggers a repair action if a node reports consecutive unhealthy status reports for a given time threshold, such as when a node broadcasts a "NotReady" status, fails to broadcast any status, or runs out of disk space.

## Secure Mitigation
Enable auto-repair for your GKE cluster node pools using:
gcloud container node-pools update POOL_NAME --cluster=CLUSTER_NAME --region=REGION --enable-autorepair

