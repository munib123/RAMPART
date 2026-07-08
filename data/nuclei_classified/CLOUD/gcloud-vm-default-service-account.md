# Vulnerability: VM Instance Using Default Service Account
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-vm-default-service-account.yaml`)

## Description
Ensure that your Google Compute Engine instances are not configured to use the default Google Cloud service account in order to implement the principle of least privilege (POLP) and secure the access to your cloud resources. The default Compute Engine service account, named <project-number>-compute@developer.gserviceaccount.com, is associated with the Editor role at the project level, which allows read and write access to most Google Cloud Platform (GCP) services.

## Secure Mitigation
Create a new service account with minimal required permissions and update VM instances to use it instead of the default Compute Engine service account. Note that this requires stopping and restarting the instances.

