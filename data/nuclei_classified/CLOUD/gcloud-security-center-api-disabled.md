# Vulnerability: Security Command Center API Disabled
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-security-center-api-disabled.yaml`)

## Description
To access historical security findings and asset data in Security Command Center, ensure that the Security Command Center API is enabled within your Google Cloud account. If the API is not enabled, certain security features and monitoring capabilities will be unavailable.

## Secure Mitigation
Enable the Security Command Center API for each Google Cloud project to maintain proper security monitoring and threat detection capabilities. This can be done through the Google Cloud Console or using the `gcloud services enable securitycenter.googleapis.com` command.

