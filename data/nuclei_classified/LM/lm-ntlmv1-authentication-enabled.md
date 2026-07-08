# Vulnerability: LM and NTLMv1 Authentication Enabled
**Classification:** LM
**Source:** Nuclei Template (`lm-ntlmv1-authentication-enabled.yaml`)

## Description
Checks if LM and NTLMv1 authentication protocols are enabled, which are insecure.

## Secure Mitigation
Disable LM and NTLMv1 and enforce NTLMv2 or Kerberos for secure authentication.

