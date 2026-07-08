# Vulnerability: Dataproc Cluster Not Using Customer-Managed Keys
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-dataproc-no-cmk.yaml`)

## Description
Ensure that your Google Cloud Dataproc clusters on Compute Engine are encrypted with Customer-Managed Keys (CMKs) in order to control the cluster data encryption/decryption process. You can create and manage your own Customer-Managed Keys (CMKs) with Cloud Key Management Service (Cloud KMS). Cloud KMS provides secure and efficient encryption key management, controlled key rotation, and revocation mechanisms.

## Secure Mitigation
Re-create your Dataproc clusters with Customer-Managed Keys using Cloud KMS. Configure a key ring and CMK in Cloud KMS, then specify the key when creating the cluster using the '--gce-pd-kms-key' flag or through the console.

