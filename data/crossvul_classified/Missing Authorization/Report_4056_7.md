# CrossVul Fix Pair: Missing Authorization in ruby
**Pair ID:** 4056_7
**Vulnerability Class:** Missing Authorization
**CWE:** CWE-862
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4056_7`)

## Vulnerability Information & PoC

## Description
Missing Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```ruby
Lines 1-25 of the vulnerable file.

# Copyright (C) 2012-2016 Zammad Foundation, http://zammad-foundation.org/

class Auth
  class Internal < Auth::Base

    def valid?(user, password)

      return false if user.blank?

      if PasswordHash.legacy?(user.password, password)
        update_password(user, password)
        return true
      end

      PasswordHash.verified?(user.password, password)
    end

    private

    def update_password(user, password)
      user.password = PasswordHash.crypt(password)
      user.save
    end
  end
end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -12,7 +12,11 @@
         return true
       end
 
-      PasswordHash.verified?(user.password, password)
+      password_verified = PasswordHash.verified?(user.password, password)
+
+      raise Exceptions::NotAuthorized, 'Please verify your account before you can login!' if !user.verified && user.source == 'signup' && password_verified
+
+      password_verified
     end
 
     private
```
