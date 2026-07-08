# Vulnerability: OS Login Not Required
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-org-os-login.yaml`)

## Description
Ensure that "Require OS Login" constraint policy is enforced at the GCP organization level in order to enable OS Login feature on all newly created Google Cloud projects within your organization. The OS Login provides you with centralized and automated SSH key pair management.

## Secure Mitigation
Enable the "Require OS Login" policy at the organization level using the 'gcloud alpha resource-manager org-policies enable-enforce' command with the compute.requireOsLogin constraint.

