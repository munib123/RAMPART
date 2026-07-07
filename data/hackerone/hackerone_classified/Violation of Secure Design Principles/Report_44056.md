# HackerOne Report: USER PRIVACY VIOLATED (PRIVATE DATA GETTING TRANSFER OVER INSECURE CHANNEL ) 
**Report ID:** 44056
**Vulnerability Class:** Violation of Secure Design Principles

## Vulnerability Information & PoC
Hello Team ,

##Description : 
this report is about how a users private data is getting exploded over insecure channel .
while testing the iOS App of Vimeo , i am analyzing all the traffics and came to know the video which is uploaded in my account and which privacy setting is private only is getting exposed over HTTP via domain __pdl.vimeocdn.com__ .
i saw my own uploaded video is getting requested from that domain over HTTP .
so in this way many users private video can be exposed by attacker easily .

##POC Pic 1 : http://sd.uploads.im/2QiSa.png
##POC Pic 2 : http://sd.uploads.im/1DE3d.png

##Live POC : http://pdl.vimeocdn.com/62464/681/324557087.mp4?token=1421434056_e5acc7620a33be45549043758a368cb1 (Over HTTP)

##Fix : 
strictly enable HTTPS for all .


Thank You
Geekboy :)


## Discussion & Remediation Timeline
