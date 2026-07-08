# Vulnerability: Detailed Audit Logging Mode Not Enabled
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-org-detailed-audit-logging.yaml`)

## Description
Ensure that "Google Cloud Platform - Detailed Audit Logging Mode" policy is enforced at the organization level in order to enable Detailed Audit Logging feature for the supported Cloud Storage resources available within your GCP organization. When Detailed Audit Logging is enforced, both the request and response are included in Cloud Audit logs.

## Secure Mitigation
Enable the "Google Cloud Platform - Detailed Audit Logging Mode" policy at the organization level using the 'gcloud alpha resource-manager org-policies enable-enforce' command with the gcp.detailedAuditLoggingMode constraint.

