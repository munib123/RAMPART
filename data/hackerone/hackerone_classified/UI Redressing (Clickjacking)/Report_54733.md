# HackerOne Report: Sandboxed iframes don't show confirmation screen
**Report ID:** 54733
**Vulnerability Class:** UI Redressing (Clickjacking)

## Vulnerability Information & PoC
Just like I anticipated in 2013 http://homakov.blogspot.com/2013/04/html5-sandbox-bad-idea.html sandbox was a bad idea.

As a payment gateway you do your best to seamlessly integrate with your customers and allow showing checkout in iframes. To prevent basic clickjacking you have data-confirm attribute on Pay button.

However with HTML5 sandbox we can completely switch off Javascript in that iframe, but forms will keep working:

data:text/html,<iframe sandbox="allow-forms"
src="https://www.coinbase.com/checkouts/6d670dea8505cc8805ae2c00294599b2?c=fiZ9HYh4OROMcVtKRtEK"
style="opacity:0.1"></iframe>

After a click in the transparent iframe the payment is made. Risk: This could be used to quickly steal a couple of bitcoins from random visitors and withdrawing them automatically to external address.

## Discussion & Remediation Timeline
