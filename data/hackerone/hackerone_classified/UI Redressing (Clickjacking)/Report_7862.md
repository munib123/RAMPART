# HackerOne Report: ClickJacking
**Report ID:** 7862
**Vulnerability Class:** UI Redressing (Clickjacking)

## Vulnerability Information & PoC


It allows remote attackers to do some clickjacking which can be used for adding arbitrary tasks . Why? Almost all of your page has missing X-FRAME-OPTIONS header.

Websites are at risk of a clickjacking attack when they allow content to be embedded within a frame.

An attacker may use this risk to invisibly load the target website into their own site and trick users into clicking on links which they never intended to. An "X-Frame-Options" header should be sent by the server to either deny framing of content, only allow it from the same origin or allow it from a trusted URIs.

Attacked PoC .

Daksh


## Discussion & Remediation Timeline
