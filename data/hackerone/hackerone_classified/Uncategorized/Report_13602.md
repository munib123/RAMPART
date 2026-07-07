# HackerOne Report: Session not expired on logout
**Report ID:** 13602
**Vulnerability Class:** Uncategorized

## Vulnerability Information & PoC
factlink is  not  expiring  sessions immediately  after logout

1. log on to https://staging.factlink.com/

2. Open HTTP LIVE  HEADERS  and  login in https://staging.factlink.com/  with your correct  username and password  
3. capture  request for ex click on settings   ( https://staging.factlink.com/user/user_name/edit)
4.and  immediately logout  the  website 

5.   replay  the  captured request    and  your logged  back into  your account  without  any username and password

## Discussion & Remediation Timeline
