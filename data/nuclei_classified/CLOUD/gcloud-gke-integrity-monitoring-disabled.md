# Vulnerability: GKE Node Pools Without Integrity Monitoring
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-gke-integrity-monitoring-disabled.yaml`)

## Description
Ensure that Integrity Monitoring is enabled for your Google Kubernetes Engine (GKE) cluster nodes to monitor and automatically check the runtime boot integrity using Google Cloud Monitoring service. This feature helps verify that the boot loader and other measured components remain untampered.

## Secure Mitigation
Re-create your node pools with Integrity Monitoring enabled using:
gcloud container node-pools create POOL_NAME --cluster=CLUSTER_NAME --shielded-integrity-monitoring

