# HackerOne Report: SMTP protection not used
**Report ID:** 56177
**Vulnerability Class:** Improper Authentication - Generic

## Vulnerability Information & PoC
Hi

I'm checking your website found spf record there.
You should apply strict **SMPT policy** to stop spoofed email sending from your domain.

An attacker would send a Fake email from security@coin.space saying that Please change your password, The victim is aware of phishing attacks, But when he sees that the mail originated from security@coin.space , He has no other way than to believe it. Clicking on the link takes him to a website where certain JavaScript is executed which steals his coin.space id and pin (SESSION COOKIE). The results can be more dangerous.

```
<?php
$to = "VICTIM@example.com";
$subject = "Password Change";
$txt = "Change your password by visiting here - [VIRUS LINK HERE]l";
$headers = "From: security@coin.space";
mail($to,$subject,$txt,$headers);
?>
```

**Fix**

Your SPF record is `v=spf1 include:_spf.google.com ~all`

It should be `v=spf1 include:_spf.google.com -all`

I strongly recommend you to read this article :

https://www.digitalocean.com/community/tutorials/how-to-use-an-spf-record-to-prevent-spoofing-improve-e-mail-reliability

The problem
The article clearly shows difference between softmail and fail you should be using fail as Softmail allows anyone to send spoofed emails from your domains. in your SPF record you should replace `~` with `-` at last before all , `-` is strict which prevents all spoofed emails except if you are sending. Your bug is that you are using `~` , you should use `-`

Best Regard
**Shubham**

## Discussion & Remediation Timeline
