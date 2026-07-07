# HackerOne Report: XSS in Tagregator plugin
**Report ID:** 35036
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
This is a XSS in Tagregator plugin that affect on wordpress users
i'm making my test on alwaysdata host
target: http://diaa.alwaysdata.net/wordpress/wp-admin/post-new.php?post_type=tggr-flickr
infected input: post_title
payload: <script>alert("a7a");</script>
then get the Permalink that is generated for public user: http://diaa.alwaysdata.net/wordpress/?tggr-tweets=alerta7a
alerted !!!
 
tell me if you wanna any information
thank you 



## Discussion & Remediation Timeline
