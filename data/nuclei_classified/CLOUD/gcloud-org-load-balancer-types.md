# Vulnerability: Load Balancer Creation Not Restricted by Type
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-org-load-balancer-types.yaml`)

## Description
Ensure that only compliant load balancer types can be used to create Google Cloud load balancers for the GCP projects and folders within your organization. The list of allowed load balancer types can only include values from the following list: INTERNAL_TCP_UDP, INTERNAL_HTTP_HTTPS, EXTERNAL_NETWORK_TCP_UDP, EXTERNAL_TCP_PROXY, EXTERNAL_SSL_PROXY, EXTERNAL_HTTP_HTTPS.

## Secure Mitigation
Configure the "Restrict Load Balancer Creation Based on Load Balancer Types" policy at the organization level to explicitly specify which load balancer types are allowed. Use the 'in:' prefix followed by INTERNAL or EXTERNAL to include all internal or external types.

