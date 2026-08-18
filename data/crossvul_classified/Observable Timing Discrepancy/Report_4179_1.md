# CrossVul Fix Pair: Observable Timing Discrepancy in ruby
**Pair ID:** 4179_1
**Vulnerability Class:** Observable Timing Discrepancy
**CWE:** CWE-208
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4179_1`)

## Vulnerability Information & PoC

## Description
Observable Timing Discrepancy - In security-relevant contexts, even small variations in timing can be exploited by attackers to indirectly infer certain details about the product's internal operations.

## Vulnerable Code
```ruby
Lines 722-753 of the vulnerable file.

    end

    # Calculcates the signature from the URL and checks whether it matches the
    # value in the `signature` query parameter. Raises `InvalidSignature` if
    # the `signature` parameter is missing or its value doesn't match the
    # calculated signature.
    def verify_url(url)
      path, query = url.split("?")

      params    = Rack::Utils.parse_query(query.to_s)
      signature = params.delete("signature")

      query = Rack::Utils.build_query(params)

      verify_signature("#{path}?#{query}", signature)
    end

    def verify_signature(string, signature)
      if signature.nil?
        fail InvalidSignature, "missing \"signature\" param"
      elsif signature != generate_signature(string)
        fail InvalidSignature, "provided signature does not match the calculated signature"
      end
    end

    # Uses HMAC-SHA-256 algorithm to generate a signature from the given string
    # using the secret key.
    def generate_signature(string)
      OpenSSL::HMAC.hexdigest(OpenSSL::Digest::SHA256.new, secret_key, string)
    end
  end
end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -739,7 +739,7 @@
     def verify_signature(string, signature)
       if signature.nil?
         fail InvalidSignature, "missing \"signature\" param"
-      elsif signature != generate_signature(string)
+      elsif !Rack::Utils.secure_compare(signature, generate_signature(string))
         fail InvalidSignature, "provided signature does not match the calculated signature"
       end
     end
```
