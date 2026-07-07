# HackerOne Report: open redirect in https://slack.com
**Report ID:** 6035
**Vulnerability Class:** Open Redirect

## Vulnerability Information & PoC
Navigate to Https://slack.com
append "/link?url=url=http://bing.com" or enter any website of your choice with http://
vulnerable link https://slack.com/link?url=http://bing.com
notice that user is redirected to bing.com without being validated or notified

## Discussion & Remediation Timeline
