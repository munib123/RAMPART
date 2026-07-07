# HackerOne Report: CSV Injection in polldaddy.com
**Report ID:** 92353
**Vulnerability Class:** Uncategorized

## Vulnerability Information & PoC
Hello,

We can inject commands in any fields of a member in an email group (=2*10 for example), and when it's exported to CSV it will be evaluated to 20 in the corresponding cell, this enables an attacker to spread malware and execute system level commands on a victim's machine if the victim downloaded the CSV file.

Steps to reproduce:
1-  Create an email group and name it anything.
2- Add a member with =2*10 in their firstname, lastname, and custom data.
3- Export as CSV and open in Excel or any similar program, the evaluated value will replace the =2*10 expression.

References: Report #90415 was about the same issue.

Thanks,

strukt


## Discussion & Remediation Timeline
