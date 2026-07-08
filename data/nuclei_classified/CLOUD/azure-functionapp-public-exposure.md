# Vulnerability: Exposed Azure Functions
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-functionapp-public-exposure.yaml`)

## Description
To follow Azure cloud security best practices and prevent public exposure, ensure that the functions managed with Microsoft Azure Function App are not publicly accessible. An Azure function is considered publicly accessible when it is configured to allow inbound access through the default (public) endpoint.

## Secure Mitigation
Configure Azure Functions to restrict access from the public network by setting the 'publicNetworkAccess' to 'Disabled'.

