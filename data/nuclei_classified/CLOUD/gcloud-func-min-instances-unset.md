# Vulnerability: Unset Minimum Instances for Cloud Functions
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-func-min-instances-unset.yaml`)

## Description
To minimize cold start latency and enhance performance, ensure that your Google Cloud Functions have a sufficient number of warm instances configured.

## Secure Mitigation
Configure the serviceConfig.minInstanceCount parameter for your Google Cloud Functions to an appropriate value that suits your workload demands.

