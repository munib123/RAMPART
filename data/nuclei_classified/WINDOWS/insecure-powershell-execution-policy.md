# Vulnerability: Insecure PowerShell Execution Policy - Detect
**Classification:** WINDOWS
**Source:** Nuclei Template (`insecure-powershell-execution-policy.yaml`)

## Description
Checks if the PowerShell Execution Policy is set to an insecure level, which could allow unauthorized or malicious scripts to run.

## Secure Mitigation
Set execution policy to RemoteSigned or AllSigned according to your organization's policy.

