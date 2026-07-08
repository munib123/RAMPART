# Vulnerability: OS Login Not Enabled for GCP Projects
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-oslogin-disabled.yaml`)

## Description
Ensure that the OS Login feature is enabled at the Google Cloud Platform (GCP) project level in order to provide you with centralized and automated SSH key pair management. OS Login ensures that SSH keys are mapped with Google Cloud IAM users, facilitating centralized management of SSH access.

## Secure Mitigation
Enable OS Login at the project level by setting the "enable-oslogin" metadata key to "TRUE". Note that enabling OS Login disables metadata-based SSH key configurations on all instances within the project.

