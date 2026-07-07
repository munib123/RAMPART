# HackerOne Report: SSRF vulnerability (access to metadata server on EC2 and OpenStack)
**Report ID:** 53088
**Vulnerability Class:** Information Disclosure

## Vulnerability Information & PoC
In bug [#50537](https://hackerone.com/reports/50537), **haquaman** reported a SSRF vulnerability in the meme creation section of Phabricator. Ticket [T6755](https://secure.phabricator.com/T6755) was created and the HackerOne issue was closed as "Won't fix".

[T6755](https://secure.phabricator.com/T6755) states that *"attackers can use the machine's ability to access the network, which may allow them to find services (and, in some rare cases, interact with services that have very, very weak authentication and act over HTTP GET)"*.

Hoewever, some common deployement scenarios (using Amazon EC2 or OpenStack) include a "metadata" web server listening on a multicast IP (169.254.169.254):
- EC2: http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html
- OpenStack:http://docs.openstack.org/admin-guide-cloud/content/section_metadata-service.html

Given the multicast IP address, this server can only reached from the instance itself.

Plenty of interesting information are stored at /latest/meta-data/ ([hostname](http://169.254.169.254/latest/meta-data/hostname), private and public IP addresses, ...). However, the worst scenario is auto-starting instances, where a startup script is stored in [/latest/user-data](http://169.254.169.254/latest/user-data). These startup scripts may include passwords, private keys, source code, ...

Test URLs:
```
http://169.254.169.254/latest/meta-data/hostname
http://169.254.169.254/latest/user-data
```

Outside of EC2 and OpenStack, some services are commonly bound to localhost, including monitoring software, noSQL databases, administration interfaces, ...

## Discussion & Remediation Timeline
