# Vulnerability: Exceeded SSL Certificate Validity Period
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-certificate-validity-exceeded.yaml`)

## Description
Ensure that SSL certificates managed with Google Cloud Certificate Manager don't have a validity period greater than 398 days (13 months). This is to enhance security by reducing the risk of certificate compromise and misuse, while aligning with industry standards and support from modern web browsers.

## Secure Mitigation
Review and adjust the renewal configurations for SSL certificates to ensure their validity periods do not exceed 398 days.

