# Vulnerability: Secrets Manager Not In Use
**Classification:** CLOUD
**Source:** Nuclei Template (`secret-manager-not-inuse.yaml`)

## Description
Ensure that Amazon Secrets Manager service is used in your AWS account to manage access credentials (i.e. secrets) such as API keys, OAuth tokens and database credentials.

## Secure Mitigation
Ensure AWS Secrets Manager is used to securely store, manage, and rotate sensitive credentials such as API keys, database passwords, and tokens, and remove hard-coded secrets from applications.

