# HackerOne Report: Full Path Disclosure (FPD) in www.localize.im
**Report ID:** 9256
**Vulnerability Class:** Information Disclosure

## Vulnerability Information & PoC
Hi,
I found an information disclosure vulnerability/Full Path Disclosure on your application.

Proof of Concept
-------------------------
GET  : https://www.localize.im/projects/[projiect ID/languages/[Language ID]
POST CONTENT: 
`CSRFToken=TOKEN&updatePhrases[previous][yxr][0]=&updatePhrases[edits][yxr][0]=&updatePhrases[previous][yxq][0]=&####LotsOfPhrases######&updatePhrases[secret]=[SecredCodes]&updatePhrases[translatorID]=[ID]`

Just Add "[]" after any of those *updatePhrases[previous][ID][0]*

### The information from page:
> **Warning: trim() expects parameter 1 to be string, array given in /srv/data/web/vhosts/www.localize.im/htdocs/index.php on line 191**

I Also Added a Screenshot of that FPD as attachment..
Hope You'll fix this one..
Thanks

## Discussion & Remediation Timeline
