# HackerOne Report: HTTP Response Splitting (CRLF injection) in report_story
**Report ID:** 52042
**Vulnerability Class:** Uncategorized

## Vulnerability Information & PoC
Hi,

I would like to report a HTTP Response Splitting vulnerability in https://twitter.com/i/safety/report_story that allows attackers to inject arbitrary headers and contents in the response. 

## PoC:
https://twitter.com/i/safety/report_story?next_view=report_story_start&source=reporttweet&reported_user_id=1&reporter_user_id=1&is_media=true&is_promoted=true&reported_tweet_id=%E5%98%8A%E5%98%8DSet-Cookie:%20test

## Details:
The page will set cookie for the parameter *reported_tweet_id*. However, it doesn't validate strictly if it is a number. Although there is a protection against CRLF injection by detecting the presence of any *NewLine* character (0x0a), it can be bypassed with characters encoded in UTF-8 as the the page will try to convert them back to the original Unicode form and extract the last byte. For example, *%E5%98%8A* => *U+560A* => *0A*.

## Discussion & Remediation Timeline
