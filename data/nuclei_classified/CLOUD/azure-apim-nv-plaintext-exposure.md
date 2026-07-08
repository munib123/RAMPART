# Vulnerability: Azure API Management Non-Encrypted Named Values Exposure
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-apim-nv-plaintext-exposure.yaml`)

## Description
Ensure that all the named values used to define secret data within Azure API Management policies are encrypted in order to prevent the exposure of credentials and secrets.

## Secure Mitigation
Convert all named values storing secrets to use the secret (encrypted) type in Azure API Management to mitigate the risk of exposing sensitive information.

