# HackerOne Report: User Enumeration and Guessable User Account Attack on WORDPRESS
**Report ID:** 16439
**Vulnerability Class:** Uncategorized

## Vulnerability Information & PoC
Hello,

I found another bug on https://wordpress.com.

Here any hacker can find out all registered users on wordpress.com.
Here are the details of the same. 

How is wordpress.com is working?
============================

1. You have Reset Password Page --> https://en.wordpress.com/wp-login.php?action=lostpassword
2. When user enter correct registered email-id, a reset password link is sent to user's email and a message 'Check your e-mail for the confirmation link.' is shown.
3. When user enter incorrect unregistered email-id, a message 'I'm sorry, but we weren't able to find a user with that login information.' is shown.

Now, this is how it is working.

Proof of concept :
===============
Server returns Status 200 ---> Not found.
Server returns Status 302 ----> Found.
Server returns Status 500 -----> Internal server error.

Now, server returns Status 500 only when same email-id / username is entered again and again to spam the user.
But, it works. I have attached POC screen shots. Please have a look. 

Possible fixes :
================

1. Regardless of what email-id is entered, server should always return a Status=Found - 302.
2. Then redirect to other page.
3. Error message should be changed to something like 'If user exists, email will be sent.'


Hope, this is sufficient for proving this vulnerability.

You may feel free to ask any questions you may have.
I will be happy explaining it to the depth. :)

Thank You,
Pranav

## Discussion & Remediation Timeline
