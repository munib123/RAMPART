# Vulnerability: Remotely Registration Enabled
**Classification:** REMOTELY
**Source:** Nuclei Template (`remotely-registration-enabled.yaml`)

## Description
Checks if the Remotely self-hosted remote desktop and collaboration web application has its user registration endpoint enabled, potentially allowing anyone to register without invitation.

## Secure Mitigation
Disable open registration if not required by setting 'RequireInvitationCodeForRegistration' to true in the Remotely configuration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/Identity/Account/Register
GET {{BaseURL}}/Account/Register
```

