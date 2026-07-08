# Vulnerability: PfSense Known Default Account - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`known-default-account.yaml`)

## Description
PfSense configured known default accounts are recommended to be deleted. In order to attempt access to known devices' platforms, an attacker can use the available database of the known default accounts for each platform or operating system. Known default accounts are often, but not limited to, 'admin'.

