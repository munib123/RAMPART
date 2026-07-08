# Vulnerability: Default Google-Managed Encryption for Cloud SQL Not Restricted
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-org-sql-default-encryption.yaml`)

## Description
Ensure that the use of Google-managed encryption keys for Cloud SQL database instances is disabled at the GCP organization level in order to enforce the use of Customer-Managed Keys (CMKs) and have full control over SQL database encryption/decryption process. Note: This organization policy is not retroactive, therefore any existing database instances using Google-managed encryption are not impacted unless they are updated or refreshed.

## Secure Mitigation
Enable the "Restrict Default Google-Managed Encryption for Cloud SQL Instances" policy at the organization level using the 'gcloud alpha resource-manager org-policies enable-enforce' command with the sql.disableDefaultEncryptionCreation constraint.

