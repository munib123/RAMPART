# Vulnerability: VM Instance Deletion Protection Not Enabled
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-vm-deletion-protection-disabled.yaml`)

## Description
Ensure that your production Google Compute Engine instances have Deletion Protection feature enabled in order to protect them from being accidentally deleted. With Deletion Protection safety feature enabled, you have the guarantee that your VM instances cannot be accidentally deleted and make sure that your production environment remains safe.

## Secure Mitigation
Enable deletion protection for your production VM instances. You can enable this feature for an existing instance regardless of its current status - stopping the instance is not required.

