# Vulnerability: GKE Clusters Without Cloud Logging Enabled
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-gke-logging-disabled.yaml`)

## Description
Ensure that logging is enabled for your Google Kubernetes Engine (GKE) clusters to collect logs emitted by your Kubernetes applications and the GKE infrastructure. Once enabled, the logging feature sends logs and metrics to a remote aggregator to reduce the risk of tampering in case of a breach locally.

## Secure Mitigation
Enable Cloud Logging for your GKE clusters using:
gcloud container clusters update CLUSTER_NAME --region=REGION --logging=SYSTEM,WORKLOAD,API_SERVER,CONTROLLER_MANAGER,SCHEDULER

