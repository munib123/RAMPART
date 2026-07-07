# HackerOne Report: Dashboard panel embedded onto itself causes a denial of service
**Report ID:** 85011
**Vulnerability Class:** Uncontrolled Resource Consumption

## Vulnerability Information & PoC
I know this may not qualify for a bounty since it's a DoS, but I believe you'd rather get sensitive reports through HackerOne rather than Maniphest. (PS: mongoose.)

Steps to reproduce
================
* In Dashboards, create a new **Text Panel** (let's say it would get the object reference `W1` on creation).
* In the **Create New Panel** dialog, embed the panel view onto itself with Remarkup: `{W1}`
* Phabricator should now bravely attempt to render this, and choke.

Impact
======
Significantly disruptive in an install where any user may create a dashboard (I think that's true by default), since they would then be able to embed this eldritch panel in, say, a Maniphest comment, forever ruining rendering for all of task, feed, and likely homepage, views.

## Discussion & Remediation Timeline
