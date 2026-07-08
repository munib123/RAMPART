# Vulnerability: Windows Automatic Updates Disabled
**Classification:** WINDOWS
**Source:** Nuclei Template (`windows-auto-update-disabled.yaml`)

## Description
Detected Windows automatic updates were found disabled, leaving the system vulnerable to unpatched security flaws.

## Secure Mitigation
Enable automatic updates via Group Policy: Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates > set to Auto download and schedule install.

