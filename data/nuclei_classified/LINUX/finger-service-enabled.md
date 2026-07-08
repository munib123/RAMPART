# Vulnerability: Linux Finger Should Be Disabled
**Classification:** LINUX
**Source:** Nuclei Template (`finger-service-enabled.yaml`)

## Description
The Finger service was enabled on the system and exposed user account details to unauthorized users, which could have been used in password-based attacks or user enumeration.It was checked in both xinetd and systemd environments.

