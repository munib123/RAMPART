# CrossVul Fix Pair: Improper Restriction of Excessive Authentication Attempts in ruby
**Pair ID:** 3913_0
**Vulnerability Class:** Improper Restriction of Authentication Attempts
**CWE:** CWE-307
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3913_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Excessive Authentication Attempts - The product does not implement sufficient measures to prevent multiple failed authentication attempts within a short time frame, making it more susceptible to brute force attacks.

## Vulnerable Code
```ruby
Lines 85-128 of the vulnerable file.

      # returns the user if success, nil otherwise.
      def authenticate(*credentials, &block)
        raise ArgumentError, 'at least 2 arguments required' if credentials.size < 2

        if credentials[0].blank?
          return authentication_response(return_value: false, failure: :invalid_login, &block)
        end

        if @sorcery_config.downcase_username_before_authenticating
          credentials[0].downcase!
        end

        user = sorcery_adapter.find_by_credentials(credentials)

        unless user
          return authentication_response(failure: :invalid_login, &block)
        end

        set_encryption_attributes

        unless user.valid_password?(credentials[1])
          return authentication_response(user: user, failure: :invalid_password, &block)
        end

        if user.respond_to?(:active_for_authentication?) && !user.active_for_authentication?
          return authentication_response(user: user, failure: :inactive, &block)
        end

        @sorcery_config.before_authenticate.each do |callback|
          success, reason = user.send(callback)

          unless success
            return authentication_response(user: user, failure: reason, &block)
          end
        end

        authentication_response(user: user, return_value: user, &block)
      end

      # encrypt tokens using current encryption_provider.
      def encrypt(*tokens)
        return tokens.first if @sorcery_config.encryption_provider.nil?

        set_encryption_attributes
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -102,10 +102,6 @@
 
         set_encryption_attributes
 
-        unless user.valid_password?(credentials[1])
-          return authentication_response(user: user, failure: :invalid_password, &block)
-        end
-
         if user.respond_to?(:active_for_authentication?) && !user.active_for_authentication?
           return authentication_response(user: user, failure: :inactive, &block)
         end
@@ -116,6 +112,10 @@
           unless success
             return authentication_response(user: user, failure: reason, &block)
           end
+        end
+
+        unless user.valid_password?(credentials[1])
+          return authentication_response(user: user, failure: :invalid_password, &block)
         end
 
         authentication_response(user: user, return_value: user, &block)
```
