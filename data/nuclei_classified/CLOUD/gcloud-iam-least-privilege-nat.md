# Vulnerability: Least Privilege Access for Cloud NAT Management
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-iam-least-privilege-nat.yaml`)

## Description
Ensure that IAM roles with administrative permissions are not assigned to IAM identities (users, groups, and service accounts) managing Cloud NAT resources. This helps enforce the Principle of Least Privilege (POLP) by granting members (principals) only the minimum access necessary to complete their tasks.

## Secure Mitigation
Review the IAM roles assigned to IAM identities managing Cloud NAT and ensure only least-privilege roles such as `roles/compute.networkUser` are assigned.

