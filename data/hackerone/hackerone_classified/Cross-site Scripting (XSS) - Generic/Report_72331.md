# HackerOne Report: XSS at Bulk editing ProductVariants
**Report ID:** 72331
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
Steps to Reproduce:

1.Create a Product with Title and Description as ` "><img src=x onerror=prompt(133)>`
2. Now goto https://blahblah.myshopify.com/admin/products/inventory
3. Select the Product created at Step 1 and Click on Edit variants

and XSS will be triggered


## Discussion & Remediation Timeline
