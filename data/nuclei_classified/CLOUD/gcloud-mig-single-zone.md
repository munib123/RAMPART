# Vulnerability: Managed Instance Group Not Configured for Multiple Zones
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-mig-single-zone.yaml`)

## Description
Ensure that Managed Instance Groups (MIGs) are spread across multiple zones within a Google Cloud region for high availability and fault tolerance. Spreading application load across multiple Google Cloud zones with MIGs is crucial for enhancing the availability, resilience, and performance of your application. When you allocate your MIG instances across multiple zones, you can guarantee the continuous availability and functionality of your application even during failures or outages.

## Secure Mitigation
Re-create your Managed Instance Groups with multiple zones configuration. Select "Multiple zones" for location, choose a region and desired zones, and set "Target distribution shape" to "Even" for balanced instance distribution.

