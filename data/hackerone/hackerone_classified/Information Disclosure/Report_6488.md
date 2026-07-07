# HackerOne Report: Weak Ciphers Enabled
**Report ID:** 6488
**Vulnerability Class:** Information Disclosure

## Vulnerability Information & PoC
Vulnerability Details:-
I detected that weak ciphers are enabled during secure communication (SSL).
You should allow only strong ciphers on your web server to protect secure communication with your visitors.

Impact:-
Attackers might decrypt SSL traffic between your server and your visitors.

Remedy:-
Configure your web server to disallow using weak ciphers.

POC Link :- https://www.ssllabs.com/ssltest/analyze.html?d=www.khanacademy.org&s=23.23.224.106

## Discussion & Remediation Timeline
