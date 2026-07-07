# HackerOne Report: XSS on ecommerce.shopify.com
**Report ID:** 56779
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
Hello! I would like to report about XSS on ecommerce.shopify.com domain.

Here is a PoC that gives You alert box with "123" content: https://ecommerce.shopify.com/grader?url=imdb.jurgens.lv

This Ecommerce Store Grader Tool gives You a list of sources of image tags that should have "alt" attribute on tested website (screenshot "where.png"). So, on Your website (imdb.jurgens.lv in my case), You can create <img> tag with the "src" attribute value "111<img src=1 onerror=alert(123)>". Then put link to Your website to this Grader Tool and after that it will show You error block "Some of the images on your homepage are missing ALT tags." which will contain Your <img> tag "src" attribute with embed <img> tag there.

You can see full example of source on http://imdb.jurgens.lv

Generally, this vulnerability exists because of no filtering in shown "src" attributes.

Thanks!




## Discussion & Remediation Timeline
