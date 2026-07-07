# HackerOne Report: XSS in myshopify.com Admin site in TAX Overrides
**Report ID:** 62427
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
POC:
If you create a collection such as "><IMG SRC=x onerror=prompt(7)> and then go to Settings / Taxes and select "Add a tax override" then on the "Add Tax Override for Rest of World" select the previously created collection of "><IMG SRC=x onerror=prompt(7)> you can see it on the screen (addtax.png).

If you press the recycle bin "Delete Entire Override" (delete.png) then  XSS is happening (xss.png)

Thanks


## Discussion & Remediation Timeline
