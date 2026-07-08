# Vulnerability: Azure App Service FTPS-Only Access Not Enabled
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-appservice-ftps-only-not-enabled.yaml`)

## Description
Ensure that your Azure App Services web applications enforce FTPS-only access to encrypt FTP traffic. FTPS (Secure FTP) is used to enhance security for your Azure web application as it adds an extra layer of security to the FTP protocol, and help you to comply with the industry standards and regulations.

## Secure Mitigation
Configure the Azure App Services to enforce FTPS-only access in the Azure portal or use Azure CLI commands to modify the FTPS settings.

