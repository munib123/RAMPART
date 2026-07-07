# HackerOne Report: comment out causes information disclosure
**Report ID:** 57125
**Vulnerability Class:** Information Disclosure

## Vulnerability Information & PoC
Hi there

Go to General setting (https://your-domain.myshopify.com/admin/settings/general), set Homepage Title to <!-- and change Name to "> plus HTML Tag like words. Some data will be leaked in the place of Title in the home page. This is dangerous because sometimes title contains highly confidential data such as cart_token, checkout_token, email, session_hash, and so on. Ticket ID is 1559798.

## Discussion & Remediation Timeline
