# Vulnerability: Azure App Service HTTPS-Only Not Enforced
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-appservice-https-only-not-enforced.yaml`)

## Description
Ensure that your Azure App Service web applications redirect all non-secure HTTP traffic to HTTPS in order to encrypt the communication between applications and web clients. HTTPS uses the Secure Sockets Layer (SSL)/Transport Layer Security (TLS) protocol to provide a secure connection, which is both encrypted and authenticated. This adds an extra layer of security to the HTTP requests made to the web application.

## Secure Mitigation
Enable the HTTPS-only feature on all Azure App Services to enforce all traffic to be encrypted and secure.

