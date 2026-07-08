# Vulnerability: Google Cloud Ignore File Exposure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`gcloudignore-file.yaml`)

## Description
Detected exposed .gcloudignore files which may reveal directory structure,deployment configurations, and sensitive project information used by Google Cloud SDK (gcloud) during deployments.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.gcloudignore
```

