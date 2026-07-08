# Vulnerability: Azure App Service Client Certificate Not Required
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-appservice-client-cert-disabled.yaml`)

## Description
Ensure that your Microsoft Azure App Service web applications are configured to require an SSL certificate from all incoming requests, for security and compliance purposes. Once the certificate is implemented, only web clients that have this valid SSL certificate will be able to reach your web application. By default, incoming client certificates are disabled for Azure App Service web applications.

## Secure Mitigation
Configure Azure App Services to require SSL certificates for incoming requests to enhance security and compliance with regulations.

