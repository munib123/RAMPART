# Vulnerability: Azure App Service HTTP/2 Not Enabled
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-appservice-http2-not-enabled.yaml`)

## Description
Ensure that your Microsoft Azure App Service web applications are using the latest version of the HTTP protocol (i.e. HTTP/2) in order to make your web applications load faster. HTTP 2.0 represents a major upgrade of the HTTP/1.1 protocol, with the primary goals of reducing the impact of latency and connection load on web servers through full request and response multiplexing, minimizing protocol overhead via HTTP header field compression, and supporting HTTP request prioritization and server push.

## Secure Mitigation
Enable HTTP/2 on your Azure App Service web applications to improve their performance and adhere to modern web standards.

