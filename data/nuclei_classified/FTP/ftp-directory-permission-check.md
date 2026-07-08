# Vulnerability: FTP Directory Access Permission Check
**Classification:** FTP
**Source:** Nuclei Template (`ftp-directory-permission-check.yaml`)

## Description
Ensure that the FTP home directory does not include the "Everyone" group in its access permissions. Granting access to this group may allow unauthorized users to view, modify, or tamper with FTP files.

## Secure Mitigation
Remove the "Everyone" group from FTP home directory permissions using the following methods:
- IIS Manager: Review and adjust the FTP site's home directory settings.
- File Explorer: Right-click the directory, select "Properties" → go to the "Security" tab, and remove the "Everyone" group.

