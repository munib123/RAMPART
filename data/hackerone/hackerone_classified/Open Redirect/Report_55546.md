# HackerOne Report: Open Redirect after login at http://ecommerce.shopify.com
**Report ID:** 55546
**Vulnerability Class:** Open Redirect

## Vulnerability Information & PoC
Hi,

The users can be redirected to some other site which is in control of the attacker from http://ecommerce.shopify.com/accounts

Let's say user is attacker asked victim to login from the here :
http://ecommerce.shopify.com/accounts?found_email=true&return_to=.mx%2F&user[email]=email@email.com

When victim enters the password he is redirected to http://ecommerce.shopify.com.mx/
This com.mx can be changed to multiple like .es .tw etc

These can be controlled by the attacker and used in other attacks



## Discussion & Remediation Timeline
