# Vulnerability: GKE Clusters Without Cost Allocation Enabled
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-gke-cost-allocation-disabled.yaml`)

## Description
Ensure that cost allocation is enabled for your Google Kubernetes Engine (GKE) clusters to gain detailed insights into resource usage. This feature allows you to break down resource consumption by Kubernetes namespaces and labels, making it easier to associate costs with specific entities and access detailed cost reports through billing data exported to BigQuery.

## Secure Mitigation
Enable cost allocation for your GKE clusters using:
gcloud container clusters update CLUSTER_NAME --region=REGION --enable-cost-allocation

