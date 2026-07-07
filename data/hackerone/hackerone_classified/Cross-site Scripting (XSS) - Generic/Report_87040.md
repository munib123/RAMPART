# HackerOne Report: XSS on OAuth authorize/authenticate endpoint
**Report ID:** 87040
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
Hi,
I would like to report an issue where certain endpoints on twitter.com and api.twitter.com is vulnerable to XSS.

##Detail
The redirection page after authorization/authentication does not sanitize the *oauth_callback* parameter.

##PoC
1. Go to http://innerht.ml/pocs/twitter-oauth-xss (Please use IE or something that hasn't implemented CSP)
2. Click on Authorize app
3. Alert pops up

Note: it also affects api.twitter.com as they both have the same endpoints

##Repo step
1. Obtain the request token (https://api.twitter.com/oauth/request_token) where parameter *oauth_callback* contains HTML like ```javascript%3A%2F%2F"><script>alert(document.domain)</script>```
2. Redirect the victim to the authorize/authenticate page with the token

## Discussion & Remediation Timeline
