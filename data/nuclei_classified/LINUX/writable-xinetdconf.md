# Vulnerability: /etc/(x)inetd.conf Permission Check
**Classification:** LINUX
**Source:** Nuclei Template (`writable-xinetdconf.yaml`)

## Description
The /etc/xinetd.conf or /etc/inetd.conf file was writable by non-root users, allowing them to register malicious services that executed with root privileges. This check verified that the file was owned by root and had secure permissions.

