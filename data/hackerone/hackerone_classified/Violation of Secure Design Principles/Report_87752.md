# HackerOne Report: gallery_plus: Content Spoofing 
**Report ID:** 87752
**Vulnerability Class:** Violation of Secure Design Principles

## Vulnerability Information & PoC
Attacker can send his messages directly through url. He can easily put his message on error message parameter .
Like that
http://192.168.0.107/owncloud/index.php/apps/galleryplus/error?message=Welcome to owncloud. You can get pro account by sending us 10 usd directly to our official paypal example@example.com. Thanks.&code=0


Thanks.

## Discussion & Remediation Timeline
