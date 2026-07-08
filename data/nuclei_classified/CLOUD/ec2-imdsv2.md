# Vulnerability: Enforce IMDSv2 on EC2 Instances
**Classification:** CLOUD
**Source:** Nuclei Template (`ec2-imdsv2.yaml`)

## Description
Ensure all EC2 instances use Instance Metadata Service Version 2 (IMDSv2) for enhanced security when requesting instance metadata, protecting against certain types of attacks that target the older version, IMDSv1.

## Secure Mitigation
Modify the EC2 instance metadata options to set `HttpTokens` to `required`, enforcing the use of IMDSv2. This can be done via the AWS Management Console, CLI, or EC2 API.

