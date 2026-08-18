# CrossVul Fix Pair: Authentication Bypass by Spoofing in ruby
**Pair ID:** 4369_0
**Vulnerability Class:** Authentication Bypass
**CWE:** CWE-290
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4369_0`)

## Vulnerability Information & PoC

## Description
Authentication Bypass by Spoofing - This attack-focused weakness is caused by incorrectly implemented authentication schemes that are subject to spoofing attacks.

## Vulnerable Code
```ruby
Lines 87-127 of the vulnerable file.


        fail!(:nonce_mismatch, CallbackError.new(:nonce_mismatch, 'nonce mismatch'))
      end

      def client_id
        @client_id ||= if id_info.nil?
                         options.client_id
                       else
                         id_info['aud'] if options.authorized_client_ids.include? id_info['aud']
                       end
      end

      def user_info
        user = request.params['user']
        return {} if user.nil?

        @user_info ||= JSON.parse(user)
      end

      def email
        user_info['email'] || id_info['email']
      end

      def first_name
        user_info.dig('name', 'firstName')
      end

      def last_name
        user_info.dig('name', 'lastName')
      end

      def prune!(hash)
        hash.delete_if do |_, v|
          prune!(v) if v.is_a?(Hash)
          v.nil? || (v.respond_to?(:empty?) && v.empty?)
        end
      end

      def client_secret
        payload = {
          iss: options.team_id,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -104,7 +104,7 @@
       end
 
       def email
-        user_info['email'] || id_info['email']
+        id_info['email']
       end
 
       def first_name
```
