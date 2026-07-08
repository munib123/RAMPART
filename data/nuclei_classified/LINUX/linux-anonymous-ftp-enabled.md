# Vulnerability: Linux Anonymous FTP Access Enabled
**Classification:** LINUX
**Source:** Nuclei Template (`linux-anonymous-ftp-enabled.yaml`)

## Description
FTP account allows malicious users to exploit it to log in anonymously and write to directories, potentially gaining unauthorized access or executing local exploits.This template checks for signs of anonymous FTP being enabled via /etc/passwd, vsFTPD, or ProFTPD configuration files.

