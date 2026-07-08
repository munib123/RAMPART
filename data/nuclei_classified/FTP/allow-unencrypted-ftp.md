# Vulnerability: Allow Unencrypted FTP
**Classification:** FTP
**Source:** Nuclei Template (`allow-unencrypted-ftp.yaml`)

## Description
Verifies if the FTP server allows unencrypted connections, which can expose sensitive data.

## Secure Mitigation
Configure FTP to require encrypted connections using SSL/TLS.

