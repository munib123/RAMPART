# CrossVul Fix Pair: Insufficient Session Expiration in ruby
**Pair ID:** 2590_2
**Vulnerability Class:** Insufficient Session Expiration
**CWE:** CWE-613
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2590_2`)

## Vulnerability Information & PoC

## Description
Insufficient Session Expiration - According to WASC, Insufficient Session Expiration is when a web site permits an attacker to reuse old session credentials or session IDs for authorization.

## Vulnerable Code
```ruby
Lines 1-21 of the vulnerable file.

module OpenProject
  module Authentication
    module Strategies
      module Warden
        ##
        # Temporary strategy necessary as long as the OpenProject authentication has
        # not been unified in terms of Warden strategies and is only locally
        # applied to the API v3.
        class Session < ::Warden::Strategies::Base
          def valid?
            session
          end

          def authenticate!
            user = user_id ? User.find(user_id) : User.anonymous

            success! user
          end

          def user_id
            Hash(session)['user_id']
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,3 +1,5 @@
+require 'open_project/authentication/session_expiry'
+
 module OpenProject
   module Authentication
     module Strategies
@@ -7,8 +9,10 @@
         # not been unified in terms of Warden strategies and is only locally
         # applied to the API v3.
         class Session < ::Warden::Strategies::Base
+          include ::OpenProject::Authentication::SessionExpiry
+
           def valid?
-            session
+            session && !session_ttl_expired?
           end
 
           def authenticate!
```
