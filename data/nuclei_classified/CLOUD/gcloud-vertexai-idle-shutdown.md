# Vulnerability: Idle Shutdown Not Enabled for Vertex AI Notebooks
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-vertexai-idle-shutdown.yaml`)

## Description
Ensure that the Idle Shutdown feature is enabled for your Google Cloud Vertex AI notebook instances to optimize costs. Inactive notebook instances continue to incur charges, and Idle Shutdown automatically stops them after a period of inactivity (i.e., no running commands or UI connections), reducing unneeded spending. Vertex AI stops charging for CPUs/GPUs once the notebook instance is shut down.

## Secure Mitigation
Enable idle shutdown for Vertex AI notebook instances using the 'gcloud workbench instances update' command with metadata parameter 'idle-timeout-seconds'. Example: --metadata 'idle-timeout-seconds=10800' for 3-hour timeout.

