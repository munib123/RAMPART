# HackerOne Report: XSS https://delivery.shopifyapps.com/  (Digital Downloads App  in myshopify.com)
**Report ID:** 81441
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
Hello
Installing the Digital Downloads App in *.myshopify.com
1-install the app  https://apps.shopify.com/digital-downloads
2-select product and click Add Digital Attachment 
3-click to upload file and upload file with name <svg onload=alert(1)>
the code  <svg onload=alert(1)> will execute XSS

<span class="file-name"><strong>Success:</strong> <svg onload="alert(1)"/></span>

tested in firefox

Hadji Samir
 

## Discussion & Remediation Timeline
