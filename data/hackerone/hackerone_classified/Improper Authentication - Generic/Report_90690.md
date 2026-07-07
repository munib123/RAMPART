# HackerOne Report: change Login Services settings without owner access
**Report ID:** 90690
**Vulnerability Class:** Improper Authentication - Generic

## Vulnerability Information & PoC
Hi

in settings -> account owner can set login service for staff members!
this is only available for owners, and full access admins can't see or change this values!

admin with setting access can send a "POST" request to shop.json and change this settings!


steps:

- get access token for one full access admin (you can send request to xauth or sniff it from mobile device)
- send request with POST method to "https://~ShopName~.myshopify.com/admin/shop.json"

data:

{"shop":{"google_apps_domain":"anydomain","google_apps_login_enabled":true}}

google_apps_login_enabled
google_apps_domain


so any admin just with setting access can modify this option,this must limited to owner!



## Discussion & Remediation Timeline
