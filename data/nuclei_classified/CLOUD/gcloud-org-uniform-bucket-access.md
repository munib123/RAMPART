# Vulnerability: Uniform Bucket-Level Access Not Enforced
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-org-uniform-bucket-access.yaml`)

## Description
Ensure that "Enforce uniform bucket-level access" policy is enabled for your Google Cloud Platform (GCP) organization in order to enforce uniform bucket-level access for all Google Cloud Storage buckets available in your organization. Enforcing uniform bucket-level access disables Access Control Lists (ACLs) for all Cloud Storage resources (buckets and objects) so that access is granted exclusively through Cloud IAM service.

## Secure Mitigation
Enable the "Enforce uniform bucket-level access" policy at the organization level using the 'gcloud alpha resource-manager org-policies enable-enforce' command with the storage.uniformBucketLevelAccess constraint.

