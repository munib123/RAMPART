# Vulnerability: Kubernetes Fake Ingress Certificate - Detect
**Classification:** SSL
**Source:** Nuclei Template (`kubernetes-fake-certificate.yaml`)

## Description
Kubernetes Fake Ingress Certificate is a feature in Kubernetes that allows users to create and use fake or self-signed SSL/TLS certificates for testing purposes without having to obtain a real SSL/TLS certificate from a trusted Certificate Authority (CA).

## Secure Mitigation
Purchase or generate a proper SSL certificate for this service.

