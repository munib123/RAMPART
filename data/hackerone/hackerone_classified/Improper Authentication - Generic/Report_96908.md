# HackerOne Report: An administrator without the 'Settings' permission is able to see payment gateways
**Report ID:** 96908
**Vulnerability Class:** Improper Authentication - Generic

## Vulnerability Information & PoC
Description
====
An administrator who lacks the 'Settings' permission is not able to see the shops payment gateways through the UI.  But the endpoint `shop.myshopify.com/admin/payment_gateways.json` does disclose payment gateways to the unprivileged user.

Mitigation
====
Restrict the endpoint in question to be only accessible with the correct permission set.

## Discussion & Remediation Timeline
