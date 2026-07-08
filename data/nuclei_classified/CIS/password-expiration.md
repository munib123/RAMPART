# Vulnerability: Ensure Password Expiration is Configured
**Classification:** CIS
**Source:** Nuclei Template (`password-expiration.yaml`)

## Description
The PASS_MAX_DAYS setting in /etc/login.defs defines how long a password may be used before it must be changed.To comply with CIS Ubuntu Linux Benchmark, this value should be set to a number greater than 0 and less than or equal to 365.

## Secure Mitigation
Edit /etc/login.defs and ensure the line is set to: PASS_MAX_DAYS 365 (or another value between 1 and 365).Verify the change with: grep -Pi -- '^\h*PASS_MAX_DAYS\h+\d+\b' /etc/login.defs

