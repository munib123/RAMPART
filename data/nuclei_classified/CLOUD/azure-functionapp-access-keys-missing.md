# Vulnerability: Azure Function Access Keys Configuration
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-functionapp-access-keys-missing.yaml`)

## Description
To follow Azure cloud security best practices and prevent anonymous access, ensure that all the HTTP-triggered Azure functions managed with Microsoft Azure Function App are configured to use access keys to securely invoke functions via URLs. Access keys with a HOST scope (i.e., function keys) can be used to access all HTTP-triggered functions within the Azure Function App.

## Secure Mitigation
Configure access keys for HTTP-triggered functions in Azure Function App to enforce secure and authorized function invocations.

