# Vulnerability: Enable Lifecycle Management for Cloud Storage Objects
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-lifecycle-management-not-enabled.yaml`)

## Description
Ensure that your Google Cloud Storage buckets are configured with lifecycle management rules to optimize object management and reduce storage costs. Lifecycle management rules help automate actions such as downgrading or deleting older objects based on user-defined conditions.

## Secure Mitigation
Enable lifecycle management rules for your Cloud Storage buckets to automate actions like deleting or downgrading storage class of objects based on conditions.

