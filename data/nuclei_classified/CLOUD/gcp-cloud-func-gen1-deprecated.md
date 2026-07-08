# Vulnerability: Deprecated 1st Generation Google Cloud Functions
**Classification:** CLOUD
**Source:** Nuclei Template (`gcp-cloud-func-gen1-deprecated.yaml`)

## Description
Ensure that none of your Google Cloud functions are 1st (first) generation functions. 1st generation Google Cloud functions are considered deprecated and no longer receive updates or support, making them less secure, less performant, and lacking in new features compared to newer generations.

## Secure Mitigation
Migrate all 1st generation Google Cloud functions to newer generation runtimes as recommended by Google to ensure continued support and access to the latest features and security enhancements.

