# Vulnerability: User Home Directory and Shell Environment File Ownership & Permission
**Classification:** LINUX
**Source:** Nuclei Template (`home-env-permission.yaml`)

## Description
Shell startup and environment files (e.g., .bashrc, .bash_profile, .bash_logout) were not owned by the user or root and had insecure write permissions.Malicious users could manipulate environment variables or inject commands.

