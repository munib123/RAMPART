# Vulnerability: Anonymous FTP Disabled Check
**Classification:** FTP
**Source:** Nuclei Template (`ftp-anonymous-check.yaml`)

## Description
Ensure that anonymous FTP authentication is disabled on all FTP sites. Allowing anonymous access permits unauthenticated users to connect, which can lead to serious security vulnerabilities.

## Secure Mitigation
Disable anonymous FTP authentication using IIS Manager:
- Open IIS Manager.
- Navigate to the FTP site → FTP Authentication.
- Set "Anonymous Authentication" to Disabled.

