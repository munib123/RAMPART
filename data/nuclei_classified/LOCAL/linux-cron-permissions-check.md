# Vulnerability: Cron Access File Ownership & Permissions
**Classification:** LOCAL
**Source:** Nuclei Template (`linux-cron-permissions-check.yaml`)

## Description
/etc/cron.allow and /etc/cron.deny (if present) were required to be owned by root (UID 0) with strict 640 permissions.If neither file existed, only the root user could use cron, which was considered the safe default behavior.

