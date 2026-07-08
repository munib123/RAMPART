# Vulnerability: Artifact Registry Vulnerability Scanning Not Enabled
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-vuln-scan-missing.yaml`)

## Description
Ensure that vulnerability scanning for Google Cloud Artifact Registry repositories is enabled in order to find security weaknesses in your container images before deploying them and help prevent security breaches.

## Secure Mitigation
Enable the Container Scanning API for each Artifact Registry by visiting the API & services page in the Google Cloud Console and enabling `containerscanning.googleapis.com`.

