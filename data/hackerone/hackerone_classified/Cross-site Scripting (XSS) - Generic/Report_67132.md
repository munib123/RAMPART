# HackerOne Report: XSS at Bulk editing products
**Report ID:** 67132
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
after following above the steps in #67125 goto  Bulk editing products:

for me the url was:
 https://img-src-x-onerror-prompt1-24.myshopify.com/admin/bulk?resource_name=Product&edit=variants.sku%2Cvariants.price%2Cvariants.compare_at_price&message=&return_to=%2Fadmin%2Fproducts&ids=1151578433

it is also vulnerable to xss
(Change the requierd fields in above url according to your shop)


## Discussion & Remediation Timeline
