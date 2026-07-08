# Vulnerability: run-parts - Privilege Escalation
**Classification:** CODE
**Source:** Nuclei Template (`privesc-run-parts.yaml`)

## Description
The run-parts command in Linux is used to run all the executable files in a directory. It is commonly used for running scripts or commands located in a specific directory, such as system maintenance scripts in /etc/cron.daily. The run-parts command provides a convenient way to execute multiple scripts or commands in a batch manner.

