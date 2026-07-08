# Vulnerability: Ensure Minimum Password Days is Configured
**Classification:** CIS
**Source:** Nuclei Template (`password-min-days.yaml`)

## Description
The PASS_MIN_DAYS setting in /etc/login.defs defines the minimum number of days required between password changes.This prevents users from rapidly cycling through passwords to bypass password history requirements.

## Secure Mitigation
Edit /etc/login.defs and ensure the line is set to: PASS_MIN_DAYS 1 (or another value greater than 0).Verify the change with: grep -Pi -- '^\h*PASS_MIN_DAYS\h+\d+\b' /etc/login.defs

