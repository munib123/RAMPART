# HackerOne Report: Session Fixation disclosing email address
**Report ID:** 2582
**Vulnerability Class:** Information Disclosure

## Vulnerability Information & PoC
Desc:
Session fixation occurs due to SessionID in URL. A valid session-URL should be only a one time use. In this case a valid session-URL remains active for infinite time. The browser/cache may store this unique Session-URL and disclose EMAIL address of the user.

Working:
1>Register
2>One registering, you will redirected to unique URL: https://slack.com/go/x-2xxxxx-f8xx7#signup
3>This link remains useable and valid and doesn't have an expiry.
4>Anyone having access to the browser history can access the link and hence the email is disclosed.

Fix:
One time use of the URL
Use of Expiry time (for ex: 10 mins) or so


## Discussion & Remediation Timeline
