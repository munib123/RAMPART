# Vulnerability: No Serverless VPC Access in Google Cloud Functions
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-func-no-vpc-access.yaml`)

## Description
Ensure that your Google Cloud functions are configured to use Serverless VPC Access in order to connect functions directly to your VPC network, allowing access to other VPC resources such as VM instances, MemoryStore instances, or any other cloud resources with an internal IP address. Without Serverless VPC Access, these functions may not be able to communicate efficiently with other resources in the same VPC.

## Secure Mitigation
Configure Serverless VPC Access for your Google Cloud functions by setting the vpcConnector parameter to the name of an already configured VPC connector in your project settings.

