# HackerOne Report: Phabricator Diffusion application allows unauthorized users to delete mirrors
**Report ID:** 38965
**Vulnerability Class:** Improper Authentication - Generic

## Vulnerability Information & PoC
I have succesfully reproduced this issue following these steps:
 
- Creating a repository with an administrator user
 
- Checking that my "guest" user hasn't access to the newly created repository:
 
  http://phabricator/diffusion/TEST/edit/
 
- However, the guest user does have access to delete the mirror:
 
  http://phabricator/diffusion/TEST/mirror/delete/1/
 
 You can review the lack of permission-checks in the file: applications/diffusion/controller/DiffusionMirrorDeleteController.php

## Discussion & Remediation Timeline
