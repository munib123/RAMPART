# Vulnerability: Unsecured Backend Services in Google Cloud Load Balancers
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-lb-backend-unsecured.yaml`)

## Description
Ensure that the backend services associated with your Google Cloud load balancers are protected with edge security policies provided by the Cloud Armor service in order to shield your backend services from a range of potential attacks. Edge security policies let you control access to your cloud resources at the Google Cloud Platform (GCP) network edge.

## Secure Mitigation
Attach an edge security policy to your backend services via the Google Cloud Console or using the Cloud Armor APIs to enhance security at your network's edge.

