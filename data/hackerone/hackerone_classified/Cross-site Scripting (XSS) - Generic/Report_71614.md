# HackerOne Report: XSS in Myshopify Admin Site in DISCOUNTS
**Report ID:** 71614
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
POC

1. Go to Customers and add a new search group named "><img src=x onerror=prompt(7) See creategroup.png
2. Go to Discounts and add a Discount Code based on Customer group and choose the one created above
3. Click Save

XSS in discounts occur (discountxss.png)

## Discussion & Remediation Timeline
