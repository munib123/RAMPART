# CrossVul Fix Pair: Cryptographic Issues in ruby
**Pair ID:** 5836_0
**Vulnerability Class:** Cryptographic Issues - Generic
**CWE:** CWE-310
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5836_0`)

## Vulnerability Information & PoC

## Description
Cryptographic Issues

## Vulnerable Code
```ruby
Lines 1-18 of the vulnerable file.

# Copyright (c) 2008-2013 Michael Dvorkin and contributors.
#
# Fat Free CRM is freely distributable under the terms of MIT license.
# See MIT-LICENSE file or http://www.opensource.org/licenses/mit-license.php
#------------------------------------------------------------------------------
# Be sure to restart your server when you modify this file.

# Your secret key for verifying the integrity of signed cookies.
# If you change this key, all old signed cookies will become invalid!
# Make sure the secret is at least 30 characters and all random,
# no regular words or you'll be exposed to dictionary attacks.

# PLEASE NOTE: This secret token must be changed in your fork of Fat Free CRM.
# This problem is mitigated when running Fat Free CRM as a Rails Engine.

if defined?(FatFreeCRM::Application)
  FatFreeCRM::Application.config.secret_token = '51aa366864a80316a85cff0d3762347f4ae3d029d548bef034d56e82b1a2ffac5353ee6719d9b64e4354e2a0b1a901679f46a851c360a2ea377188e4b196b6b6'
end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3,16 +3,23 @@
 # Fat Free CRM is freely distributable under the terms of MIT license.
 # See MIT-LICENSE file or http://www.opensource.org/licenses/mit-license.php
 #------------------------------------------------------------------------------
+
 # Be sure to restart your server when you modify this file.
 
-# Your secret key for verifying the integrity of signed cookies.
+# Your secret key is used for verifying the integrity of signed cookies.
 # If you change this key, all old signed cookies will become invalid!
+
 # Make sure the secret is at least 30 characters and all random,
 # no regular words or you'll be exposed to dictionary attacks.
+# You can use `rake secret` to generate a secure secret key.
 
-# PLEASE NOTE: This secret token must be changed in your fork of Fat Free CRM.
-# This problem is mitigated when running Fat Free CRM as a Rails Engine.
+# Make sure your secret_key_base is kept private
+# if you're sharing your code publicly.
 
 if defined?(FatFreeCRM::Application)
-  FatFreeCRM::Application.config.secret_token = '51aa366864a80316a85cff0d3762347f4ae3d029d548bef034d56e82b1a2ffac5353ee6719d9b64e4354e2a0b1a901679f46a851c360a2ea377188e4b196b6b6'
+  if Rails.env == 'test'
+    FatFreeCRM::Application.config.secret_token = '51aa366864a80316a85cff0d3762347f4ae3d029d548bef034d56e82b1a2ffac5353ee6719d9b64e4354e2a0b1a901679f46a851c360a2ea377188e4b196b6b6'
+  else
+    raise "Please run 'rake ffcrm:secret' to generate a secret token."
+  end
 end
```
