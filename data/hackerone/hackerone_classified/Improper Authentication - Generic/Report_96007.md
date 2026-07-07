# HackerOne Report: Domain takoever - https://sellocdn.com
**Report ID:** 96007
**Vulnerability Class:** Improper Authentication - Generic

## Vulnerability Information & PoC
Hi,

While performing some DNS recon activities, I identified the following domain sellocdn.com, owned and operated by Shopify (see whois below). The DNS record is pointing to Heroku, but it hasn't be claimed on Heroku. This would allow a malicious user  to login to Heroku and claim the domain, and host malicious content of their choosing on http://sellocdn.com.

i understand that this is out of scope, but I thought I would point it out since I found it.

Registry Registrant ID:
Registrant Name: Shopify Hostmaster
Registrant Organization: Shopify Inc.
Registrant Street: 126 York St.  200
Registrant City: Ottawa
Registrant State/Province: ON
Registrant Postal Code: K1N 5T5
Registrant Country: CA
Registrant Phone: +1.(613) 241-2828
Registrant Phone Ext:
Registrant Fax:
Registrant Fax Ext:
Registrant Email: domains@shopify.com

PoC - navigate to http://sellocdn.com

## Discussion & Remediation Timeline
