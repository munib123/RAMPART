# HackerOne Report: XSS at http://vk.com on IE using flash files
**Report ID:** 66121
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
**Steps**

+ Open the below url in **Internet Explorer**
 
```
http://vk.com/swf/photo_uploader_lite.swf?h=h?&onMouseOver=document.write(window.location.hash.substr(1))#<script>alert(document.domain)</script>
```

+ Just hover your mouse over the page.

**Minor Observations**

+ No "X-Content-Type-Options: nosniff" header allows IE to play the flash file directly whereas other browsers present download dialog as the content type served is **application/zip**.
+ No X-Frame options will allow this attack to be placed inside an iframe and run stealthily.
+ Other flash files such as **http://vk.com/swf/CaptureImg.swf** will also be vulnerable in a similar fashion.

## Discussion & Remediation Timeline
