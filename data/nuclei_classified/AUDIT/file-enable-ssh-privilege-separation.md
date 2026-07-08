# Vulnerability: Enable Privilege Separation in SSH
**Classification:** AUDIT
**Source:** Nuclei Template (`file-enable-ssh-privilege-separation.yaml`)

## Description
Privilege separation in SSH enhances security by running the SSH daemon with minimal privileges, reducing the risk of privilege escalation. It limits the impact of vulnerabilities, preventing full system compromise if SSH is exploited.

## Secure Mitigation
Set UsePrivilegeSeparation yes in /etc/ssh/sshd_config to enhance security and restart the SSH service.

