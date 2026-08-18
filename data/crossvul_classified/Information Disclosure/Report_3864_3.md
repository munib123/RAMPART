# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in ruby
**Pair ID:** 3864_3
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3864_3`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```ruby
Lines 44-84 of the vulnerable file.

      #
      def renew_secret
        @raw_secret = Doorkeeper::OAuth::Helpers::UniqueToken.generate
        secret_strategy.store_secret(self, :secret, @raw_secret)
      end

      # We keep a volatile copy of the raw secret for initial communication
      # The stored refresh_token may be mapped and not available in cleartext.
      #
      # Some strategies allow restoring stored secrets (e.g. symmetric encryption)
      # while hashing strategies do not, so you cannot rely on this value
      # returning a present value for persisted tokens.
      def plaintext_secret
        if secret_strategy.allows_restoring_secrets?
          secret_strategy.restore_secret(self, :secret)
        else
          @raw_secret
        end
      end

      # This is the right way how we want to override ActiveRecord #to_json
      #
      # @return [String] entity attributes as JSON
      #
      def as_json(options = {})
        hash = super

        hash["secret"] = plaintext_secret if hash.key?("secret")
        hash
      end

      def authorized_for_resource_owner?(resource_owner)
        Doorkeeper.configuration.authorize_resource_owner_for_client.call(self, resource_owner)
      end

      private

      def generate_uid
        self.uid = Doorkeeper::OAuth::Helpers::UniqueToken.generate if uid.blank?
      end

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -61,15 +61,27 @@
         end
       end
 
-      # This is the right way how we want to override ActiveRecord #to_json
+      # Represents client as set of it's attributes in JSON format.
+      # This is the right way how we want to override ActiveRecord #to_json.
       #
-      # @return [String] entity attributes as JSON
+      # Respects privacy settings and serializes minimum set of attributes
+      # for public/private clients and full set for authorized owners.
+      #
+      # @return [Hash] entity attributes for JSON
       #
       def as_json(options = {})
-        hash = super
-
-        hash["secret"] = plaintext_secret if hash.key?("secret")
-        hash
+        # if application belongs to some owner we need to check if it's the same as
+        # the one passed in the options or check if we render the client as an owner
+        if (respond_to?(:owner) && owner && owner == options[:current_resource_owner]) ||
+           options[:as_owner]
+          # Owners can see all the client attributes, fallback to ActiveModel serialization
+          super
+        else
+          # if application has no owner or it's owner doesn't match one from the options
+          # we render only minimum set of attributes that could be exposed to a public
+          only = extract_serializable_attributes(options)
+          super(options.merge(only: only))
+        end
       end
 
       def authorized_for_resource_owner?(resource_owner)
@@ -99,6 +111,49 @@
 
       def enforce_scopes?
         Doorkeeper.config.enforce_configured_scopes?
+      end
+
+      # Helper method to extract collection of serializable attribute names
+      # considering serialization options (like `only`, `except` and so on).
+      #
+      # @param options [Hash] serialization options
+      #
+      # @return [Array<String>]
+      #   collection of attributes to be serialized using #as_json
+      #
+      def extract_serializable_attributes(options = {})
+        opts = options.try(:dup) || {}
+        only = Array.wrap(opts[:only]).map(&:to_s)
+
+        only = if only.blank?
+                 serializable_attributes
+               else
+                 only & serializable_attributes
+               end
+
+        only -= Array.wrap(opts[:except]).map(&:to_s) if opts.key?(:except)
+        only.uniq
+      end
+
+      # We need to hook into this method to allow serializing plan-text secrets
+      # when secrets hashing enabled.
+      #
+      # @param key [String] attribute name
+      #
+      def read_attribute_for_serialization(key)
+        return super unless key.to_s == "secret"
+
+        plaintext_secret || secret
+      end
+
+      # Collection of attributes that could be serialized for public.
+      # Override this method if you need additional attributes to be serialized.
+      #
+      # @return [Array<String>] collection of serializable attributes
+      def serializable_attributes
+        attributes = %w[id name created_at]
+        attributes << "uid" unless confidential?
+        attributes
       end
     end
 
```
