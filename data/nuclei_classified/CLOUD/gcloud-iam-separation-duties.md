# Vulnerability: Enforce Separation of Duties for Service-Account Related Roles
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-iam-separation-duties.yaml`)

## Description
Ensure that separation of duties is enforced for all Google Cloud Platform (GCP) service-account related roles. This security principle prevents fraud and human error by dispersing the tasks and associated privileges for a specific business process among multiple users/members. Specifically, your GCP service accounts should not have the Service Account Admin and Service Account User roles assigned simultaneously.

## Secure Mitigation
Review and modify the roles assigned to GCP service accounts ensuring that no service account has both the Service Account Admin and Service Account User roles assigned at the same time.

