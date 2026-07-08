# Vulnerability: /etc/syslog and /etc/rsyslog.conf Permission Check
**Classification:** LINUX
**Source:** Nuclei Template (`syslog-rsyslog-permission.yaml`)

## Description
The /etc/syslog.conf or /etc/rsyslog.conf file was not owned by root or had insecure permissions,allowing attackers to manipulate logging settings to evade detection.

