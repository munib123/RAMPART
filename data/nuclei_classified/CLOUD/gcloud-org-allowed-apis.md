# Vulnerability: Google Cloud APIs and Services Not Restricted
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-org-allowed-apis.yaml`)

## Description
Ensure that all the Google Cloud APIs and services restricted within your organization are defined using the "Restrict allowed Google Cloud APIs and services" organization policy. This constraint policy helps you achieve regulatory compliance by defining the set of cloud services and APIs that cannot be used within your GCP organization.

## Secure Mitigation
Configure the "Restrict allowed Google Cloud APIs and services" policy at the organization level to explicitly deny specific APIs. Note that only certain APIs can be restricted: compute.googleapis.com, deploymentmanager.googleapis.com, dns.googleapis.com, doubleclicksearch.googleapis.com, replicapool.googleapis.com, replicapoolupdater.googleapis.com, and resourceviews.googleapis.com.

