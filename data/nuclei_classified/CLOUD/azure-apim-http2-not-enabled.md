# Vulnerability: Azure API Management HTTP/2 Support Not Enabled
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-apim-http2-not-enabled.yaml`)

## Description
Ensure that your Azure API Management API gateways are configured to use HTTP/2 to increase API performance on the client-side. HTTP/2 is designed to reduce the impact of latency and connection load on servers by using features like full request and response multiplexing, minimizing protocol overhead, and supporting request prioritization and server push.

## Secure Mitigation
Enable HTTP/2 support in Azure API Management gateways by setting the 'Microsoft.WindowsAzure.ApiManagement.Gateway.Protocols.Server.Http2' property to 'true'.

