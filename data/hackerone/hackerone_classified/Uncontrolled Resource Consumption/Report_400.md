# HackerOne Report: GIF flooding
**Report ID:** 400
**Vulnerability Class:** Uncontrolled Resource Consumption

## Vulnerability Information & PoC
Current limits
---------------------
Image size: 1 MB
Image dimensions: 2048x2048px
File types: jpg/png/gif

Another image hack
---------------------
A GIF composed of 40k 1x1 images made Paperclip freeze until timeout.

As attachments I sent the file composed of 40k images, and a screenshot of the timeout.

Possible Fix
---------------------
Check if:
file size / (width * height) != ridiculous amount


## Discussion & Remediation Timeline
