# HackerOne Report: Unauthorized access to all collections, products, pages from other stores
**Report ID:** 93921
**Vulnerability Class:** Improper Authentication - Generic

## Vulnerability Information & PoC
Hi

I found a vulnerability in shopify that can leak other shops hidden objects include collection,product,page,blog

steps:

- go to "/admin/link_lists"
- click on "add link list"
- select one object from list for example collection
- open "Inspect Element"
- change value of element "link_list[links][][subject_id]" to any id from other shops
- click on save then when page reloaded you will see data in box 

this works for hidden collection, products, pages

Regards

## Discussion & Remediation Timeline
