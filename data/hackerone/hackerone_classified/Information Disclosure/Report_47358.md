# HackerOne Report: Username and sim id enum
**Report ID:** 47358
**Vulnerability Class:** Information Disclosure

## Vulnerability Information & PoC
Look at this url (GET request)
https://mobilevikings.be/en/sims/authorization/remove/admin/1036358/ - looks good - admin user detected 
https://mobilevikings.be/en/sims/authorization/remove/lloyd/1036358/ - looks good - lloyd user detected
https://mobilevikings.be/en/sims/authorization/remove/lloydxxx/1036358/ - there is no lloydxxx user
Sim card id (exist username should be used - lloyd in this case):
https://mobilevikings.be/en/sims/authorization/remove/lloyd/1036358/ - sim card id 1036358 detected
https://mobilevikings.be/en/sims/authorization/remove/lloyd/1036359/ - sim card id 1036359 detected
https://mobilevikings.be/en/sims/authorization/remove/lloyd/1036351/ - there is no sim card id 1036351

## Discussion & Remediation Timeline
