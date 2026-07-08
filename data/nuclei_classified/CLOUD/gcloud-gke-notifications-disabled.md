# Vulnerability: GKE Clusters Without Critical Notifications Enabled
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-gke-notifications-disabled.yaml`)

## Description
Ensure that critical alert notifications are enabled for your Google Kubernetes Engine (GKE) clusters to receive important Pub/Sub messages about upgrades, security bulletins, and other relevant information. This helps you stay informed about potential risks and opportunities for optimization.

## Secure Mitigation
Enable critical notifications for your GKE clusters using:
gcloud container clusters update CLUSTER_NAME --notification-config=pubsub=ENABLED,pubsub-topic=projects/PROJECT_ID/topics/TOPIC_NAME

