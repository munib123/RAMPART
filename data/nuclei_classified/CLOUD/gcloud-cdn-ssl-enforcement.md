# Vulnerability: Cloud CDN SSL/TLS Not Enforced
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-cdn-ssl-enforcement.yaml`)

## Description
Ensure that Google Cloud CDN backend bucket origins enforce HTTPS using SSL/TLS certificates in order to handle encrypted traffic. This helps to protect the integrity and confidentiality of the transmitted information.

## Secure Mitigation
Configure SSL/TLS certificates for Cloud CDN backend bucket origins and ensure all traffic is served over HTTPS by adjusting the forwarding rules and url-maps.

