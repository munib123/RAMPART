# Vulnerability: Exposed VPC Endpoint
**Classification:** CLOUD
**Source:** Nuclei Template (`vpc-endpoint-exposed.yaml`)

## Description
Identify and secure fully accessible Amazon VPC endpoints to prevent unauthorized access to AWS services.

## Secure Mitigation
Update the VPC endpoint's policy to restrict access only to authorized entities and ensure all requests are signed.

