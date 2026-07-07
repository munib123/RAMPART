# HackerOne Report: RCE due to Web Console IP Whitelist bypass in Rails 4.0 and 4.1
**Report ID:** 44513
**Vulnerability Class:** Code Injection

## Vulnerability Information & PoC
With the release of Ruby on Rails 4.2 the so called [Web Console](https://github.com/rails/web-console) was introduced. 

As the Web Console documentation states:
*Web Console is built explicitly for Rails 4.*

By default the Web Console is available in the Rails Development Environment and allows only the IPs `127.0.0.1` and `::1` to access the console in order to evaluate arbitrary Ruby statements for the purpose of debugging.

However with Rails Versions 4.1 and 4.0 the Web Console built in IP whitelist is bypassable.
This is due to the fact that Web Console parses the `request.remote_ip` to check if the IP is whitelisted with the Ruby class `IPAddr`. The Rails stack prior to 4.2 when calculating `request.remote_ip` uses [these regular expressions](https://github.com/rails/rails/blob/4-1-stable/actionpack/lib/action_dispatch/middleware/remote_ip.rb#L31-38) to strip out trusted Proxies from the HTTP Headers `X-Forwarded-For` and `Client-IP`.

Due to this parser differential an attacker might bypass the Web Console IP whitelist by supplying a HTTP header value of:

`X-Forwarded-For: 0000::1` 

This IPv6 address in the given notation would bypass the `TRUSTED_PROXIES` entry `^::1$` but match the `IPAddr` value of `::1` within Web Console.

As the Web Console is *intended* for debugging in the Development Environment this will most likely not affect Production setups, unless Web Console is explicitly enabled. But gaining RCE on Developer laptops might be fun as well ;).

I've already sent a description of this to the Rails Security Team via mail, but I've been asked to submit here again. 

The easiest mitigation of this issue would be to disallow execution of Web Console within Rails < 4.2.

## Discussion & Remediation Timeline
