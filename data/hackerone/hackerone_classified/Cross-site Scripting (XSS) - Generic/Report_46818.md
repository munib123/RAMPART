# HackerOne Report: Twitter Card - Parent Window Redirection
**Report ID:** 46818
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
Hi,
I was trying to find XSS on another website and I finally did.

After that I tried share this url on Twitter to show website owner, and noticed that I can run javascript on that iframe.


Javascript that I used on Twitter Card : 

<script>top.window.location.href="https://google.com.tr"</script>


You can watch PoC



## Discussion & Remediation Timeline
