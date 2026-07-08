# Vulnerability: VM Instance Maintenance Policy Set to Terminate
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-vm-maintenance-terminate.yaml`)

## Description
Ensure that Google Cloud Compute Engine performs live migration of your virtual machine instances during periodic infrastructure maintenance. The virtual machine maintenance behavior determines whether the VM instances are live migrated or terminated during a maintenance event. To ensure that your Google Cloud VM instances are migrated to new hardware, set "On Host Maintenance" configuration setting to "Migrate".

## Secure Mitigation
Configure the maintenance behavior to "MIGRATE" using the gcloud compute instances set-scheduling command or through the Google Cloud Console. This ensures instances are live migrated during maintenance events.

