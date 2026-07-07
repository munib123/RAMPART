# HackerOne Report: A 'Full access' administrator is able to see the shop owners user details
**Report ID:** 96890
**Vulnerability Class:** Privilege Escalation

## Vulnerability Information & PoC
Description
====

A 'Full access' administrator is usually forbidden to see the shop owners user profile. But the endpoint `shop.myshopify.com/admin/users.json` does disclose the shop owners profile. As the user listing includes all fields of users this does leak the user details of the shop owner.

A direct query to `shop.myshopify.com/admin/users/{USERID}.json` does however honer the fact that this shouldn't be allowed by returning `{ "error": "Forbidden from viewing user" }`.

Mitigation
====
Filter out the shop owner from the user listing provided by the `/admin/users.json` endpoint for 'Full access' administrators.


## Discussion & Remediation Timeline
