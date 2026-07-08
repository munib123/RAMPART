# Vulnerability: LM Hash Storage Enabled
**Classification:** WINDOWS
**Source:** Nuclei Template (`lm-hash-storage-enabled.yaml`)

## Description
Checks if LM hashes are stored, which is an insecure practice.

## Secure Mitigation
Disable LM hash storage by setting the NoLMHash registry key to prevent storing weak LM hashes.

