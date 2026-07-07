# HackerOne Report: MD5 used for Key-Auth signatures
**Report ID:** 32944
**Vulnerability Class:** Cryptographic Issues - Generic

## Vulnerability Information & PoC
https://github.com/WP-API/Key-Auth/blob/f9b74b3e4df667cfb44baba556eafde65fa3aec9/key-auth.php#L65

MD5 is vulnerable to length-extension attacks.

Maybe consider changing this to `hash_hmac('sha256', json_encode($args), $secret)`?

## Discussion & Remediation Timeline
