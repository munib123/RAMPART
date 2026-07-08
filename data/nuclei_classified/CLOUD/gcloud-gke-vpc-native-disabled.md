# Vulnerability: GKE Clusters Without VPC-Native Traffic Routing
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-gke-vpc-native-disabled.yaml`)

## Description
Ensure that VPC-native traffic routing is enabled for your Google Kubernetes Engine (GKE) clusters. This feature enhances integration with Google Cloud's VPC, improving network performance, scalability, and security through the use of alias IP address ranges.

## Secure Mitigation
Re-create your GKE clusters with VPC-native traffic routing using:
gcloud container clusters create CLUSTER_NAME --enable-ip-alias

