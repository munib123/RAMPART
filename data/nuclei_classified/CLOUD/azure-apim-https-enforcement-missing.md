# Vulnerability: Azure API Management HTTPS Enforcement Not Configured
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-apim-https-enforcement-missing.yaml`)

## Description
Ensure that your Azure API Management APIs are configured to enforce HTTPS for all API calls in order to provide secure, encrypted communication, protect data integrity, user privacy, and comply with industry standards.

## Secure Mitigation
Configure all Azure API Management APIs to enforce HTTPS by setting the URL scheme to "https" only in the API settings.

