# HackerOne Report: Clickjacking - changing role
**Report ID:** 7924
**Vulnerability Class:** UI Redressing (Clickjacking)

## Vulnerability Information & PoC
Hi,

I'm able to frame the page, when I make a frame with a opacity of 0 and a button at the position of the role switch I can change the role without the victim knowing that.

a POC screen :
http://prntscr.com/3ay0mh

a POC code : 
`<iframe src="https://app.respond.ly" style="width:100%;height:100%;margin:0;border:0;"></iframe>`

Best regards,

Olivier Beg

## Discussion & Remediation Timeline
