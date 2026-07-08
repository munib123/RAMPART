# Vulnerability: Use VPC Service Controls for Cloud Storage Buckets
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-vpc-service-controls-not-configured.yaml`)

## Description
Ensure that VPC Service Controls are used to configure a security perimeter around your Google Cloud Storage buckets to prevent data exfiltration and enhance the security posture of your cloud environment.

## Secure Mitigation
Configure VPC Service Controls with a security perimeter that includes the Cloud Storage service (storage.googleapis.com) to protect your sensitive data.

