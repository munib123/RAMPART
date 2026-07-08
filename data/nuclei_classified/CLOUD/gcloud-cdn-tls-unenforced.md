# Vulnerability: Unenforced SSL/TLS on Cloud CDN Backend Service Origins
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-cdn-tls-unenforced.yaml`)

## Description
Ensure that Google Cloud CDN backend service origins are using SSL/TLS certificates to enforce HTTPS in order to manage encrypted traffic. This helps to protect the integrity and confidentiality of the transmitted information.

## Secure Mitigation
Configure SSL/TLS certificates for your Cloud CDN backend service origins to enforce HTTPS and ensure that all communications are securely encrypted.

