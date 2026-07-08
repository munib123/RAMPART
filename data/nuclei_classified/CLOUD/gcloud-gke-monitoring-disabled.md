# Vulnerability: GKE Clusters Without Cloud Monitoring Enabled
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-gke-monitoring-disabled.yaml`)

## Description
Ensure that Cloud Monitoring is enabled for your Google Kubernetes Engine (GKE) clusters to collect metrics emitted by your Kubernetes applications and the GKE infrastructure. Cloud Monitoring helps track cluster health, application reliability, and performance metrics.

## Secure Mitigation
Enable Cloud Monitoring for your GKE clusters using:
gcloud container clusters update CLUSTER_NAME --region=REGION --monitoring=SYSTEM,API_SERVER,SCHEDULER,CONTROLLER_MANAGER,DAEMONSET,DEPLOYMENT,HPA,POD,STATEFULSET,STORAGE,CADVISOR,KUBELET,DCGM

