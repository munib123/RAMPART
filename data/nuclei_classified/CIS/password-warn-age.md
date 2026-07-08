# Vulnerability: Ensure Password Expiration Warning Days is Configured
**Classification:** CIS
**Source:** Nuclei Template (`password-warn-age.yaml`)

## Description
The PASS_WARN_AGE setting in /etc/login.defs defines the number of days before password expiration that users are warned.To comply with CIS Ubuntu Linux Benchmark, this value should be set to 7 to provide sufficient notice for users to change passwords.

## Secure Mitigation
Edit /etc/login.defs and ensure the line is set to: PASS_WARN_AGE 7.Verify the change with: grep -Pi -- '^\h*PASS_WARN_AGE\h+\d+\b' /etc/login.defs

