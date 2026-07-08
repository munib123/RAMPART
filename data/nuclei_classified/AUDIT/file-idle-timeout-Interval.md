# Vulnerability: Set SSH Idle Timeout Interval
**Classification:** AUDIT
**Source:** Nuclei Template (`file-idle-timeout-Interval.yaml`)

## Description
Missing an SSH idle timeout interval can lead to security risks by allowing unattended sessions to remain open, increasing the chance of unauthorized access or session hijacking.

## Secure Mitigation
Set ClientAliveInterval 300 and ClientAliveCountMax 0 in /etc/ssh/sshd_config to enforce an idle timeout and restart the SSH service.

