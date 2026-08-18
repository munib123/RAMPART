# CrossVul Fix Pair: Improper Authentication in ruby
**Pair ID:** 4181_1
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4181_1`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```ruby
Lines 1-35 of the vulnerable file.

require 'spec_helper'
require 'json'
require 'jwt'

describe OmniAuth::Auth0::JWTValidator do
  #
  # Reused data
  #

  let(:client_id) { 'CLIENT_ID' }
  let(:client_secret) { 'CLIENT_SECRET' }
  let(:domain) { 'samples.auth0.com' }
  let(:future_timecode) { 32_503_680_000 }
  let(:past_timecode) { 303_912_000 }
  let(:jwks_kid) { 'NkJCQzIyQzRBMEU4NjhGNUU4MzU4RkY0M0ZDQzkwOUQ0Q0VGNUMwQg' }

  let(:rsa_private_key) do
    OpenSSL::PKey::RSA.generate 2048
  end

  let(:rsa_token_jwks) do
    {
      keys: [
        {
          kid: jwks_kid,
          x5c: [Base64.encode64(make_cert(rsa_private_key).to_der)]
        }
      ]
    }.to_json
  end

  let(:jwks) do
    current_dir = File.dirname(__FILE__)
    jwks_file = File.read("#{current_dir}/../../resources/jwks.json")
    JSON.parse(jwks_file, symbolize_names: true)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -12,17 +12,17 @@
   let(:domain) { 'samples.auth0.com' }
   let(:future_timecode) { 32_503_680_000 }
   let(:past_timecode) { 303_912_000 }
-  let(:jwks_kid) { 'NkJCQzIyQzRBMEU4NjhGNUU4MzU4RkY0M0ZDQzkwOUQ0Q0VGNUMwQg' }
+  let(:valid_jwks_kid) { 'NkJCQzIyQzRBMEU4NjhGNUU4MzU4RkY0M0ZDQzkwOUQ0Q0VGNUMwQg' }
 
   let(:rsa_private_key) do
     OpenSSL::PKey::RSA.generate 2048
   end
 
-  let(:rsa_token_jwks) do
+  let(:valid_jwks) do
     {
       keys: [
         {
-          kid: jwks_kid,
+          kid: valid_jwks_kid,
           x5c: [Base64.encode64(make_cert(rsa_private_key).to_der)]
         }
       ]
@@ -91,29 +91,29 @@
     end
   end
 
-  describe 'JWT verifier jwks_key' do
+  describe 'JWT verifier jwks key parsing' do
     let(:jwt_validator) do
       make_jwt_validator
     end
 
     before do
-      stub_jwks
+      stub_complete_jwks
     end
 
     it 'should return a key' do
-      expect(jwt_validator.jwks_key(:alg, jwks_kid)).to eq('RS256')
+      expect(jwt_validator.jwks_key(:alg, valid_jwks_kid)).to eq('RS256')
     end
 
     it 'should return an x5c key' do
-      expect(jwt_validator.jwks_key(:x5c, jwks_kid).length).to eq(1)
+      expect(jwt_validator.jwks_key(:x5c, valid_jwks_kid).length).to eq(1)
     end
 
     it 'should return nil if there is not key' do
-      expect(jwt_validator.jwks_key(:auth0, jwks_kid)).to eq(nil)
+      expect(jwt_validator.jwks_key(:auth0, valid_jwks_kid)).to eq(nil)
     end
 
     it 'should return nil if the key ID is invalid' do
-      expect(jwt_validator.jwks_key(:alg, "#{jwks_kid}_invalid")).to eq(nil)
+      expect(jwt_validator.jwks_key(:alg, "#{valid_jwks_kid}_invalid")).to eq(nil)
     end
   end
 
@@ -153,8 +153,24 @@
     end
 
     before do
-      stub_jwks
-      stub_dummy_jwks
+      stub_complete_jwks
+      stub_expected_jwks
+    end
+
+    it 'should fail when JWT is nil' do
+      expect do
+        jwt_validator.verify(nil)
+      end.to raise_error(an_instance_of(OmniAuth::Auth0::TokenValidationError).and having_attributes({
+        message: "ID token is required but missing"
+      }))
+    end
+
+    it 'should fail when JWT is not well-formed' do
+      expect do
+        jwt_validator.verify('abc.123')
+      end.to raise_error(an_instance_of(OmniAuth::Auth0::TokenValidationError).and having_attributes({
+        message: "ID token could not be decoded"
+      }))
     end
 
     it 'should fail with missing issuer' do
@@ -245,6 +261,39 @@
         jwt_validator.verify(token)
       end.to raise_error(an_instance_of(OmniAuth::Auth0::TokenValidationError).and having_attributes({
         message: "Expiration time (exp) claim error in the ID token; current time (#{Time.now}) is after expiration time (#{Time.at(past_timecode + 60)})"
+      }))
+    end
+
+    it 'should pass when past expiration but within default leeway' do
+      exp = Time.now.to_i - 59
+      payload = {
+        iss: "https://#{domain}/",
+        sub: 'sub',
+        aud: client_id,
+        exp: exp,
+        iat: past_timecode
+      }
+
+      token = make_hs256_token(payload)
+      id_token = jwt_validator.verify(token)
+      expect(id_token['exp']).to eq(exp)
+    end
+
+    it 'should fail when past expiration and outside default leeway' do
+      exp = Time.now.to_i - 61
+      payload = {
+        iss: "https://#{domain}/",
+        sub: 'sub',
+        aud: client_id,
+        exp: exp,
+        iat: past_timecode
+      }
+
+      token = make_hs256_token(payload)
+      expect do
+        jwt_validator.verify(token)
+      end.to raise_error(an_instance_of(OmniAuth::Auth0::TokenValidationError).and having_attributes({
+        message: "Expiration time (exp) claim error in the ID token; current time (#{Time.now}) is after expiration time (#{Time.at(exp + 60)})"
       }))
     end
 
@@ -377,6 +426,114 @@
       }))
     end
 
+    it 'should fail when “max_age” sent on the authentication request and this claim added the “max_age” value doesn’t represent a date in the future, outside the default leeway' do
+      now = Time.now.to_i
+      auth_time = now - 121
+      max_age = 60
+      payload = {
+        iss: "https://#{domain}/",
+        sub: 'sub',
+        aud: client_id,
+        exp: future_timecode,
+        iat: past_timecode,
+        auth_time: auth_time
+      }
+
+      token = make_hs256_token(payload)
+      expect do
+        jwt_validator.verify(token, { max_age: max_age })
+        # Time.at(auth_time + max_age + leeway
+      end.to raise_error(an_instance_of(OmniAuth::Auth0::TokenValidationError).and having_attributes({
+        message: "Authentication Time (auth_time) claim in the ID token indicates that too much time has passed since the last end-user authentication. Current time (#{Time.now}) is after last auth time (#{Time.at(auth_time + max_age + 60)})"
+      }))
+    end
+
+    it 'should verify when “max_age” sent on the authentication request and this claim added the “max_age” value doesn’t represent a date in the future, outside the default leeway' do
+      now = Time.now.to_i
+      auth_time = now - 119
+      max_age = 60
+      payload = {
+        iss: "https://#{domain}/",
+        sub: 'sub',
+        aud: client_id,
+        exp: future_timecode,
+        iat: past_timecode,
+        auth_time: auth_time
+      }
+
+      token = make_hs256_token(payload)
+      id_token = jwt_validator.verify(token, { max_age: max_age })
+      expect(id_token['auth_time']).to eq(auth_time)
+    end
+
+    it 'should fail for RS256 token when kid is incorrect' do
+      domain = 'example.org'
+      sub = 'abc123'
+      payload = {
+        sub: sub,
+        exp: future_timecode,
+        iss: "https://#{domain}/",
+        iat: past_timecode,
+        aud: client_id
+      }
+      invalid_kid = 'invalid-kid'
+      token = make_rs256_token(payload, invalid_kid)
+      expect do
+        verified_token = make_jwt_validator(opt_domain: domain).verify(token)
+      end.to raise_error(an_instance_of(OmniAuth::Auth0::TokenValidationError).and having_attributes({
+        message: "Could not find a public key for Key ID (kid) 'invalid-kid'"
+      }))
+    end
+
+    it 'should fail when RS256 token has invalid signature' do
+      domain = 'example.org'
+      sub = 'abc123'
+      payload = {
+        sub: sub,
+        exp: future_timecode,
+        iss: "https://#{domain}/",
+        iat: past_timecode,
+        aud: client_id
+      }
+      token = make_rs256_token(payload) + 'bad'
+      expect do
+        verified_token = make_jwt_validator(opt_domain: domain).verify(token)
+      end.to raise_error(an_instance_of(JWT::VerificationError).and having_attributes({
+        message: "Signature verification raised"
+      }))
+    end
+
+    it 'should fail when algorithm is not RS256 or HS256' do
+      payload = {
+        iss: "https://#{domain}/",
+        sub: 'abc123',
+        aud: client_id,
+        exp: future_timecode,
+        iat: past_timecode
+      }
+      token = JWT.encode payload, 'secret', 'HS384'
+      expect do
+        jwt_validator.verify(token)
+      end.to raise_error(an_instance_of(OmniAuth::Auth0::TokenValidationError).and having_attributes({
+        message: "Signature algorithm of HS384 is not supported. Expected the ID token to be signed with RS256 or HS256"
+      }))
+    end
+
+    it 'should fail when HS256 token has invalid signature' do
+      payload = {
+        iss: "https://#{domain}/",
+        sub: 'abc123',
+        aud: client_id,
+        exp: future_timecode,
+        iat: past_timecode
+      }
+      token = make_hs256_token(payload, 'bad_secret')
+      expect do
+        # validator is configured to use "CLIENT_SECRET" by default
+        jwt_validator.verify(token)
+      end.to raise_error(an_instance_of(JWT::VerificationError))
+    end
+
     it 'should verify a valid HS256 token with multiple audiences' do
       audience = [
         client_id,
@@ -417,12 +574,43 @@
... (diff truncated)
```
