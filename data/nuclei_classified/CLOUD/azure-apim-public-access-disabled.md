# Vulnerability: Azure API Management Public Network Access Disabled with Private Endpoint
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-apim-public-access-disabled.yaml`)

## Description
Azure API Management services configured with a private endpoint should not be publicly accessible to enhance security by ensuring that the API service instance is only accessible from within your private network, over Azure Private Link, limiting exposure to potential external threats and unauthorized access.

## Secure Mitigation
Disable public network access for Azure API Management services that are configured with a private endpoint to ensure they are only accessible via Azure Private Link within the private network.

