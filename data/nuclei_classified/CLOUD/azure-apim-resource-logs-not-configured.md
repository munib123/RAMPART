# Vulnerability: Azure API Management Service Resource Logs Not Configured
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-apim-resource-logs-not-configured.yaml`)

## Description
Ensure that your Azure API Management API services are configured to use resource logs to collect valuable information on API Management operations and errors. By enabling resource logs through a diagnostic setting, you can gather extensive information on the API requests received and handled by the Azure API Management service gateway.

## Secure Mitigation
Ensure that resource logs are enabled by setting up diagnostic settings for each Azure API Management service instance. This should include capturing all logs related to API operations and errors.

