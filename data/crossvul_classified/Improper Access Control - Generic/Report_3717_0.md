# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in ruby
**Pair ID:** 3717_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3717_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```ruby
Lines 1-7 of the vulnerable file.

# Be sure to restart your server when you modify this file.

# Your secret key for verifying the integrity of signed cookies.
# If you change this key, all old signed cookies will become invalid!
# Make sure the secret is at least 30 characters and all random,
# no regular words or you'll be exposed to dictionary attacks.
Src::Application.config.secret_token = 'f466b184ef680822293d7130f57593a7087a34b5de0607c64d1ceb66fcac4dce6810a6f176feba3fbbf2489de93c0918397c0c275996eb476b2fa6079ab849c1'
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,7 +1,14 @@
-# Be sure to restart your server when you modify this file.
+require 'active_support/secure_random'
 
-# Your secret key for verifying the integrity of signed cookies.
-# If you change this key, all old signed cookies will become invalid!
-# Make sure the secret is at least 30 characters and all random,
-# no regular words or you'll be exposed to dictionary attacks.
-Src::Application.config.secret_token = 'f466b184ef680822293d7130f57593a7087a34b5de0607c64d1ceb66fcac4dce6810a6f176feba3fbbf2489de93c0918397c0c275996eb476b2fa6079ab849c1'
+begin
+  # Read token string from the file.
+  token = IO.read('/etc/katello/secret_token')
+  raise RuntimeError, 'Size is too small' if token.length < 9
+  Src::Application.config.secret_token = token.chomp
+rescue Exception => e
+  # If anything is wrong make sure the token is random. This is safe even when
+  # Katello is not configured correctly for any reason (but session is lost
+  # after each restart).
+  Rails.logger.warn "Using randomly generated secure token: #{e.message}"
+  Src::Application.config.secret_token = ActiveSupport::SecureRandom.hex(80)
+end
```
