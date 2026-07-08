# Vulnerability: IAM Users with Unrestricted Data Decryption Permissions
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-iam-unrestricted-decryption.yaml`)

## Description
Ensure that IAM users with data decryption permissions should use conditions to enforce strict controls, enhancing data protection and reducing risks of unauthorized decryption. For compliance, the Cloud KMS CryptoKey Decrypter (roles/cloudkms.cryptoKeyDecrypter), Cloud KMS Crypto Operator (roles/cloudkms.cryptoOperator), and Cloud KMS CryptoKey Encrypter/Decrypter (roles/cloudkms.cryptoKeyEncrypterDecrypter) roles must have a condition preventing data decryption with any KMS key.

## Secure Mitigation
Add IAM conditions to roles that allow decryption operations, restricting access to specific KMS keys. This can be done using resource.type and resource.name conditions in the IAM policy.

