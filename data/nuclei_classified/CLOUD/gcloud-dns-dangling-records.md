# Vulnerability: Dangling DNS Records Check
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-dns-dangling-records.yaml`)

## Description
Ensure that dangling DNS records are removed from your public Cloud DNS zones in order to maintain the integrity and authenticity of your domains/subdomains and to protect against domain hijacking.

## Secure Mitigation
Regularly audit your DNS records and associated IP addresses. Remove any DNS records that point to IP addresses no longer reserved under your Google Cloud account.

