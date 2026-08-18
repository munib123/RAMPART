# CrossVul Fix Pair: Improper Authentication in ruby
**Pair ID:** 4181_0
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4181_0`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```ruby
Lines 11-51 of the vulnerable file.

      attr_accessor :issuer, :domain

      # Initializer
      # @param options object
      #   options.domain - Application domain.
      #   options.issuer - Application issuer (optional).
      #   options.client_id - Application Client ID.
      #   options.client_secret - Application Client Secret.

      def initialize(options, authorize_params = {})
        @domain = uri_string(options.domain)

        # Use custom issuer if provided, otherwise use domain
        @issuer = @domain
        @issuer = uri_string(options.issuer) if options.respond_to?(:issuer)

        @client_id = options.client_id
        @client_secret = options.client_secret
      end

      def verify_signature(jwt)
        head = token_head(jwt)

        # Make sure the algorithm is supported and get the decode key.
        if head[:alg] == 'RS256'
          [rs256_decode_key(head[:kid]), head[:alg]]
        elsif head[:alg] == 'HS256'
          [@client_secret, head[:alg]]
        else
          raise OmniAuth::Auth0::TokenValidationError.new("Signature algorithm of #{head[:alg]} is not supported. Expected the ID token to be signed with RS256 or HS256")
        end
      end

      # Verify a JWT.
      # @param jwt string - JWT to verify.
      # @param authorize_params hash - Authorization params to verify on the JWT
      # @return hash - The verified token, if there were no exceptions.
      def verify(jwt, authorize_params = {})
        if !jwt
          raise OmniAuth::Auth0::TokenValidationError.new('ID token is required but missing')
        end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -28,17 +28,24 @@
         @client_secret = options.client_secret
       end
 
+      # Verify a token's signature. Only tokens signed with the RS256 or HS256 signatures are supported.
+      # @return array - The token's key and signing algorithm
       def verify_signature(jwt)
         head = token_head(jwt)
 
         # Make sure the algorithm is supported and get the decode key.
         if head[:alg] == 'RS256'
-          [rs256_decode_key(head[:kid]), head[:alg]]
+          key, alg = [rs256_decode_key(head[:kid]), head[:alg]]
         elsif head[:alg] == 'HS256'
-          [@client_secret, head[:alg]]
+          key, alg = [@client_secret, head[:alg]]
         else
           raise OmniAuth::Auth0::TokenValidationError.new("Signature algorithm of #{head[:alg]} is not supported. Expected the ID token to be signed with RS256 or HS256")
         end
+
+        # Call decode to verify the signature
+        JWT.decode(jwt, key, true, decode_opts(alg))
+
+        return key, alg
       end
 
       # Verify a JWT.
@@ -93,11 +100,27 @@
       end
 
       private
+      # Get the JWT decode options. We disable the claim checks since we perform our claim validation logic
+      # Docs: https://github.com/jwt/ruby-jwt
+      # @return hash
+      def decode_opts(alg)
+        {
+          algorithm: alg,
+          verify_expiration: false,
+          verify_iat: false,
+          verify_iss: false,
+          verify_aud: false,
+          verify_jti: false,
+          verify_subj: false,
+          verify_not_before: false
+        }
+      end
+
       def rs256_decode_key(kid)
         jwks_x5c = jwks_key(:x5c, kid)
 
         if jwks_x5c.nil?
-          raise OmniAuth::Auth0::TokenValidationError.new("Could not find a public key for Key ID (kid) '#{kid}''")
+          raise OmniAuth::Auth0::TokenValidationError.new("Could not find a public key for Key ID (kid) '#{kid}'")
         end
 
         jwks_public_cert(jwks_x5c.first)
```
