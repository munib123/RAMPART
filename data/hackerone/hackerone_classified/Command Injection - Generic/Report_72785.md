# HackerOne Report: CSV Injection with the CVS export feature
**Report ID:** 72785
**Vulnerability Class:** Command Injection - Generic

## Vulnerability Information & PoC
The "Download as a CSV" feature of HackerOne does not properly "escape" fields. This allows an adversary to turn a field into active content so when a response team download the csv and opens it, the active content gets executed. Here is more information about this issue: http://www.contextis.com/resources/blog/comma-separated-vulnerabilities/

Here is one method to reproduce this issue:

1. As a researcher, I can report an issue with a name starting with "=1+1"
2. As a response team, I choose to export all issues found to CSV containing the issue in (1)
3. As a response team, I now open this CSV file in excel or another spreadsheet program
4. You can see the cell containing the issue name in (1) is displayed as "2" which means the code is executed.

Mitigation:
Ensure all fields are properly "escaped" before returning the CSV file to the user.

## Discussion & Remediation Timeline
