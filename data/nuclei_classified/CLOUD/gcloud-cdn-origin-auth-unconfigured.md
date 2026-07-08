# Vulnerability: Unconfigured Cloud CDN Origin Authentication
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-cdn-origin-auth-unconfigured.yaml`)

## Description
Ensure that Cloud CDN origins are configured to authenticate access to the content available at backend (backend buckets or backend services) using signed cookies and signed URLs. Signed cookies and URLs are designed to prevent unauthorized users from bypassing the authentication process and accessing sensitive information.

## Secure Mitigation
Configure your Cloud CDN origins to use signed cookies and URLs by adding signed request keys to your backend services. This will enforce authentication on CDN-cached content, preventing unauthorized access.

