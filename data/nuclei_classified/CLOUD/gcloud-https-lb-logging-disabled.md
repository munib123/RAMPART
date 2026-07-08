# Vulnerability: Logging Disabled on HTTP(S) Load Balancers
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-https-lb-logging-disabled.yaml`)

## Description
Ensure that your Google Cloud HTTP(S) load balancers are configured to log all network traffic. Enabling logging on HTTP(S) load balancers is crucial for diagnosing issues and ensuring transparency in traffic management.

## Secure Mitigation
Enable logging on all Google Cloud HTTP(S) load balancers by configuring the logConfig.enable setting to true in the backend services settings.

