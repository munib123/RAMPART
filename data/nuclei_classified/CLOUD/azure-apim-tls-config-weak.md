# Vulnerability: Azure API Management Weak TLS Configured
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-apim-tls-config-weak.yaml`)

## Description
Ensure that your Azure API Management API gateways are not configured to use weak and deprecated TLS protocols such as TLS 1.0 and TLS 1.1. Using outdated TLS versions can expose your APIs to exploits targeting flaws in these older protocols. Ensure API gateways use the latest supported TLS version.

## Secure Mitigation
Update the Azure API Management gateway configurations to disable TLS 1.0 and TLS 1.1, ensuring only the latest TLS protocols are used. Refer to the Azure documentation on updating API gateway configurations.

