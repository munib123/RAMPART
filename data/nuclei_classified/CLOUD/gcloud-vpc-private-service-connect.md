# Vulnerability: Private Service Connect Endpoints Not Configured
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-vpc-private-service-connect.yaml`)

## Description
Ensure that Private Service Connect (PSC) endpoints are configured for your Virtual Private Cloud (VPC) networks. Private Service Connect creates a secure, private tunnel between your VPC network and Google's services (or your own services in another VPC) so traffic never touches the public internet. This enhances security and avoids complexities of managing public connections.

## Secure Mitigation
Configure Private Service Connect endpoints for your VPC networks using either the Google Cloud Console or gcloud CLI. Use the 'gcloud compute forwarding-rules create' command with appropriate parameters to set up PSC endpoints.

