# Vulnerability: Restrict Administrator Access for Service Accounts
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-service-account-admin-restriction.yaml`)

## Description
Ensure that your Google Cloud user-managed service accounts are not using privileged (administrator) roles, in order to implement the principle of least privilege and prevent any accidental or intentional modifications that may lead to data leaks and/or data loss. A user-managed service account is an identity that a virtual machine (VM) instance or an application can use to run API requests on your behalf. GCP service accounts can create, modify, or delete resources only if you grant the necessary IAM permissions, at the project or resource level.

## Secure Mitigation
Review and minimize the roles assigned to service accounts, ensuring no administrative privileges are granted unless absolutely necessary.

