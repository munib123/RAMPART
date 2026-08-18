# CrossVul Fix Pair: Incorrect Type Conversion or Cast in xml
**Pair ID:** 5277_1
**Vulnerability Class:** Type Confusion
**CWE:** CWE-704
**Language:** xml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5277_1`)

## Vulnerability Information & PoC

## Description
Incorrect Type Conversion or Cast - The product does not correctly convert an object, resource, or structure from one type to a different type.

## Vulnerable Code
```xml
Lines 14-54 of the vulnerable file.

This HTTP extension aims to provide a convenient and powerful
set of functionality for one of PHPs major applications.

It eases handling of HTTP urls, headers and messages, provides
means for negotiation of a client's preferred content type,
language and charset, as well as a convenient way to send any
arbitrary data with caching and resuming capabilities.

It provides powerful request functionality with support for
parallel requests.

Documentation:
https://mdref.m6w6.name/http
]]></description>
 <lead>
  <name>Michael Wallner</name>
  <user>mike</user>
  <email>mike@php.net</email>
  <active>yes</active>
 </lead>
 <date>2016-09-07</date>
 <version>
  <release>2.6.0beta2</release>
  <api>2.6.0</api>
 </version>
 <stability>
  <release>beta</release>
  <api>stable</api>
 </stability>
 <license uri="http://copyfree.org/content/standard/licenses/2bsd/license.txt">BSD-2-Clause</license>
 <notes><![CDATA[
+ Added http\Client\Curl\User interface for userland event loops
+ Added http\Url::IGNORE_ERRORS, http\Url::SILENT_ERRORS and http\Url::STDFLAGS
+ Added http\Client::setDebug(callable $debug)
+ Added http\Client\Curl\FEATURES constants and namespace
+ Added http\Client\Curl\VERSIONS constants and namespace
+ Added share_cookies and share_ssl (libcurl >= 7.23.0) options to http\Client::configure()
+ http\Client uses curl_share handles to properly share cookies and SSL/TLS sessions between requests
+ Improved configure checks for default CA bundles
+ Improved negotiation precision
* Fixed regression introduced by http\Params::PARSE_RFC5987: negotiation using the params parser would receive param keys without the trailing asterisk, stripped by http\Params::PARSE_RFC5987.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -31,9 +31,9 @@
   <email>mike@php.net</email>
   <active>yes</active>
  </lead>
- <date>2016-09-07</date>
+ <date>2016-09-12</date>
  <version>
-  <release>2.6.0beta2</release>
+  <release>2.6.0RC1</release>
   <api>2.6.0</api>
  </version>
  <stability>
@@ -69,6 +69,10 @@
 Changes from beta1:
 * Fixed PHP-5.3 compatibility
 * Fixed recursive calls to the event loop dispatcher
+
+Changes from beta2:
+* Fix bug #73055: crash in http\QueryString (Mike, @rc0r)
+* Fix HTTP/2 version parser for older libcurl versions (Mike)
 ]]></notes>
  <contents>
   <dir name="/">
@@ -185,6 +189,7 @@
      <file role="test" name="bug69313.phpt"/>
      <file role="test" name="bug69357.phpt"/>
      <file role="test" name="bug71719.phpt"/>
+     <file role="test" name="bug73055.phpt"/>
      <file role="test" name="client001.phpt"/>
      <file role="test" name="client002.phpt"/>
      <file role="test" name="client003.phpt"/>
```
