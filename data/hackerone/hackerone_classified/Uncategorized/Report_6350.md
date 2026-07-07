# HackerOne Report: creating titleless and non-closable bugs 
**Report ID:** 6350
**Vulnerability Class:** Uncategorized

## Vulnerability Information & PoC
Hi,

I just found that it's possible to create titleless and non-closable bugs by prepending values for the 'report[title]'  and 'report[vulnerability_information]' parameters with '%00' characters respectively.

To reproduce:
- Create a baseline request via https://hackerone.com/[program]/reports/new
- Intercept said request to allow tampering using a valid session (i.e. Burp Repeater)
- Prepend the value for 'report[title]' with '%00' (creates titleless report) or;
- Prepend the value for report[vulnerability_information]' with '%00' (create non-closable report)
- View the titleless/non-closable bug reports in the queue for [program]

Regards,

-leander




## Discussion & Remediation Timeline
