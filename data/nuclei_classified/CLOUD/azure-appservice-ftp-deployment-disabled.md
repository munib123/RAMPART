# Vulnerability: Azure App Service Plain FTP Deployment Disabled
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-appservice-ftp-deployment-disabled.yaml`)

## Description
Ensure that your Microsoft Azure App Services web applications are not configured to be deployed over plain FTP. Instead, the deployment can be disabled over FTP or performed over FTPS. FTPS (Secure FTP) is used to enhance security for your Azure web application as it adds an extra layer of security to the FTP protocol, and helps you to comply with industry standards and regulations.

## Secure Mitigation
Configure the Azure App Services to disable FTP deployment or to use FTPS, ensuring encrypted and secure file transfers.

