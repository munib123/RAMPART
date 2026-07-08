# Vulnerability: Automatic Runtime Security Updates Disabled in Google Cloud Functions
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-func-auto-runtime-updates-disabled.yaml`)

## Description
Ensure that automatic runtime security updates are enabled for your Google Cloud functions in order to keep the functions secure and protected against vulnerabilities without manual intervention.

## Secure Mitigation
Enable automatic runtime security updates for each Google Cloud function by setting the `serviceConfig.minInstanceCount` to a non-null value, ensuring functions are automatically updated with the latest security patches.

