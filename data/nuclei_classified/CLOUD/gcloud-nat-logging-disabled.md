# Vulnerability: Logging Disabled for Cloud NAT Gateways
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-nat-logging-disabled.yaml`)

## Description
Ensure that logging is enabled for your Google Cloud NAT gateways in order to log NAT connections and errors for audit and troubleshooting purposes. When logging is enabled, a log entry is generated in two scenarios: when a network connection using NAT is successfully created and when a packet is dropped due to the unavailability of NAT ports.

## Secure Mitigation
Enable logging for your Google Cloud NAT gateways by setting the `logConfig.enable` parameter to `True`. This ensures that all NAT connection and error activities are logged appropriately.

