# CrossVul Fix Pair: Server-Side Request Forgery (SSRF) in ruby
**Pair ID:** 2502_2
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**CWE:** CWE-918
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2502_2`)

## Vulnerability Information & PoC

## Description
Server-Side Request Forgery (SSRF) - By providing URLs to unexpected hosts or ports, attackers can make it appear that the server is sending the request, possibly bypassing access controls such as firewalls that prevent the attackers ...

## Vulnerable Code
```ruby
Lines 318-358 of the vulnerable file.

      # @raise [Error] If the resource has no identifier (and thus cannot be
      #   retrieved).
      # @raise [NotFound] If no resource can be found for the supplied
      #   identifier (or the supplied identifier is +nil+).
      # @raise [API::NotModified] If the <tt>:etag</tt> option is set and
      #   matches the server's.
      # @example
      #   Recurly::Account.find "heisenberg"
      #   # => #<Recurly::Account account_code: "heisenberg", ...>
      #   Use the following identifiers for these types of objects:
      #     for accounts use account_code
      #     for plans use plan_code
      #     for invoices use invoice_number
      #     for subscriptions use uuid
      #     for transactions use uuid
      def find(uuid, options = {})
        if uuid.nil? || uuid.to_s.empty?
          raise NotFound, "can't find a record with nil identifier"
        end

        uri = uuid =~ /^http/ ? uuid : member_path(uuid)
        begin
          from_response API.get(uri, {}, options)
        rescue API::NotFound => e
          raise NotFound, e.description
        end
      end

      # Instantiates and attempts to save a record.
      #
      # @return [Resource] The record.
      # @raise [Transaction::Error] A monetary transaction failed.
      # @see create!
      def create(attributes = {})
        new(attributes) { |record| record.save }
      end

      # Instantiates and attempts to save a record.
      #
      # @return [Resource] The saved record.
      # @raise [Invalid] The record is invalid.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -335,9 +335,8 @@
           raise NotFound, "can't find a record with nil identifier"
         end
 
-        uri = uuid =~ /^http/ ? uuid : member_path(uuid)
         begin
-          from_response API.get(uri, {}, options)
+          from_response API.get(member_path(uuid), {}, options)
         rescue API::NotFound => e
           raise NotFound, e.description
         end
```
