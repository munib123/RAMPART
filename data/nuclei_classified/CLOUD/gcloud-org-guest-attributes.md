# Vulnerability: Guest Attributes of Compute Engine Metadata Not Disabled
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-org-guest-attributes.yaml`)

## Description
Ensure that "Disable Guest Attributes of Compute Engine Metadata" organization policy is enforced in order to disable Compute Engine API access to the guest attributes configured for the virtual machines instances that belong to your project, folder, or organization. Guest attributes are a specific type of custom metadata that your cloud applications can write to while running on your virtual machine (VM) instance.

## Secure Mitigation
Enable the "Disable Guest Attributes of Compute Engine Metadata" policy at the organization level using the 'gcloud alpha resource-manager org-policies enable-enforce' command with the compute.disableGuestAttributesAccess constraint.

