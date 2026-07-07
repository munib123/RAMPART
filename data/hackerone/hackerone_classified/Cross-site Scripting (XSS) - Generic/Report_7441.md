# HackerOne Report: Dangerous Persistent xss
**Report ID:** 7441
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
If a person is an op in a channel, it is possible to make all the users inside the irc channel execute javascript code.
Steps to repoduce:
1.Go to a random channel where you are op.
2.Enter the following command:
/ban <script>alert(2)</script>
3.The script will execute an alert box containing 2 in all the browsers of the users inside the irc channel.

## Discussion & Remediation Timeline
