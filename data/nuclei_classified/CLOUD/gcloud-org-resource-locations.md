# Vulnerability: Resource Location Restrictions Not Configured
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-org-resource-locations.yaml`)

## Description
Ensure that the locations where location-based cloud resources can be created within your GCP organization are defined using the "Google Cloud Platform - Resource Location Restriction" organization policy. This constraint policy helps you achieve regulatory compliance by explicitly defining the locations allowed to deploy Google Cloud resources for your organization. You can specify multi-regions such as "asia" and "europe" and individual regions such as "us-east1" or "europe-west2" as allowed locations.

## Secure Mitigation
Configure the "Google Cloud Platform - Resource Location Restriction" policy at the organization level to explicitly specify allowed locations. Use the 'in:' prefix followed by location strings (e.g., in:us-locations, in:us-west1-locations) to define allowed regions.

