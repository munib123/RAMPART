# Vulnerability: Service Account Creation Not Disabled
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-org-service-account-creation.yaml`)

## Description
Ensure that the creation of Cloud IAM service accounts is prevented within your Google Cloud organization through the "Disable Service Account Creation" organization policy. This allows you to easily centralize the management of your service accounts while not restricting the other permissions that your developers and administrators have on the projects within the organization.

## Secure Mitigation
Enable the "Disable Service Account Creation" policy at the organization level using the 'gcloud alpha resource-manager org-policies enable-enforce' command with the iam.disableServiceAccountCreation constraint.

