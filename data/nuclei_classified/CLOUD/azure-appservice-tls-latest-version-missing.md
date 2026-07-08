# Vulnerability: Azure App Service TLS Latest Version Not Configured
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-appservice-tls-latest-version-missing.yaml`)

## Description
Ensure that all Microsoft Azure App Service web applications are using the latest version of TLS encryption protocol to secure the applications traffic over the Internet and comply with the industry standards. This check verifies if the minimum TLS version configured is not "1.2", indicating that the latest version of TLS is not used.

## Secure Mitigation
Configure the minimum TLS version to "1.2" in the Azure App Service settings to ensure data is encrypted with the latest security standards.

