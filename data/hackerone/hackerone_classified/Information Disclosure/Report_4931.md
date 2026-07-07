# HackerOne Report: CONCRETE5 - path disclosure.
**Report ID:** 4931
**Vulnerability Class:** Information Disclosure

## Vulnerability Information & PoC
Hi,

When you emtpy the cookie `CONCRETE5` it will throw the following error on the page :

`Warning: session_start() [function.session-start]: The session id contains illegal characters, valid characters are a-z, A-Z, 0-9 and '-,' in /home/c5host/msm_versions/012312/concrete/startup/session.php on line 22
Warning: session_start() [function.session-start]: Cannot send session cookie - headers already sent by (output started at /home/c5host/msm_versions/012312/concrete/startup/session.php:22) in /home/c5host/msm_versions/012312/concrete/startup/session.php on line 22`
`Warning: session_start() [function.session-start]: Cannot send session cache limiter - headers already sent (output started at /home/c5host/msm_versions/012312/concrete/startup/session.php:22) in /home/c5host/msm_versions/012312/concrete/startup/session.php on line 22
Warning: Cannot modify header information - headers already sent by (output started at /home/c5host/msm_versions/012312/concrete/startup/session.php:22) in /home/c5host/msm_versions/012312/concrete/libraries/view.php on line 841`

Best regards,

Olivier Beg

## Discussion & Remediation Timeline
