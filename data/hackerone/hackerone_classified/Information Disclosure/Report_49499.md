# HackerOne Report: Generating Unlimited Free Travel Gift Invites | IDOR
**Report ID:** 49499
**Vulnerability Class:** Information Disclosure

## Vulnerability Information & PoC
After registration you can invite your friends to get some offer on there first trip. Notice that this system is flawed and attacker can generate as many invites he wants without going through the system at all.

Original Invite link:

http://www.airbnb.com/c/spent1?euid=ed736125-704e-f1ec-bb76-4ca60026141d&ri=14052412&s=30

Now i tweaked euid and ri. They can take any number as input and still generated valid gift card.

**https://www.airbnb.com/c/fun?euid=2&ri=14052213&s=30**

Also we can spoof user name as well by modifying part after c. 

See poc for full demonstration: https://drive.google.com/file/d/0B0ZK8lhjLLHwcDVCdjNodmd0Qk0/view?usp=sharing

## Discussion & Remediation Timeline
