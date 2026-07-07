# HackerOne Report: Arbitrary file uploads to Amazon WS.
**Report ID:** 7929
**Vulnerability Class:** Violation of Secure Design Principles

## Vulnerability Information & PoC
Hi,

It seems one is able to upload arbitrary files to Amazon Webservices through the UI.

This allows for uploading malware such as [msf-payload-x86.jpg.exe](https://hackerone-attachments.s3.amazonaws.com/production/000/006/741/bf60ba068e72e767b93d3fa35c89a36639dd1f19/msf-payload-x86.jpg.exe?AWSAccessKeyId=AKIAJFXIS7KJADBA4QQA&Expires=1397769394&Signature=aoXXsjuCqUjReIFLzMtXYyMO5us%3D) or whatever.

Beyond free hosting this could potentially be used to entice teams into downloading stuff they probably don't want.

Actual exploitation would likely depend on obfuscating the filename to look more innocent, general human errors, a certain trust in files being served from `hackerone-attachments.*.amazonaws.com` or separate issues entirely.

I could imagine this to be working as intended but still believe it would be good to consider restrictions even if the result is to not enforce any.

I would propose to at least consider displaying a warning similar to the (excellent) one displayed when visiting an external link.

HTH,

-leander

## Discussion & Remediation Timeline
