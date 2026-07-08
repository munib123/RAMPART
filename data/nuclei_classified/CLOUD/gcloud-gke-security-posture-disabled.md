# Vulnerability: GKE Security Posture Dashboard Not Enabled
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-gke-security-posture-disabled.yaml`)

## Description
Ensure that Security Posture dashboard is enabled for your Google Kubernetes Engine (GKE) clusters. This feature integrates with other cloud services such as Cloud Logging, Policy Controller, and Binary Authorization to provide visibility into vulnerabilities, misconfigurations, and compliance risks, helping to enhance cluster security and maintain regulatory compliance.

## Secure Mitigation
Enable Security Posture for your GKE clusters using:
gcloud container clusters update CLUSTER_NAME --region=REGION --security-posture=enterprise

