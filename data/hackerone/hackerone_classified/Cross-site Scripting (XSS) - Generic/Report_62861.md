# HackerOne Report: Bulk Discount App in myshopify.com exposes http://bulkdiscounts.shopifyapps.com vulnerable to XSS
**Report ID:** 62861
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
Installing the Bulk Discount App in *.myshopify.com (which requires  a paid basic plan) makes the bulkdiscounts.shopifyapps.com vulnerable to XSS due to non sanitized input in products and collections.

POC:

1. Enter a product name or a collection such as "><img src=x onerror=prompt(document.domain)> and save it.
2. Install the Shopify BulkDiscounts App
3. Go to Apps -> Shopify BulkDiscounts
4. Click on "Create One now" or "New Discount Set"

Due to improper sanitization XSS occurs in the shopifyapps.com domain !!

Thanks

## Discussion & Remediation Timeline
