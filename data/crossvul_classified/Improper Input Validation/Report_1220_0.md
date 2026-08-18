# CrossVul Fix Pair: Improper Input Validation in ruby
**Pair ID:** 1220_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1220_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```ruby
Lines 237-277 of the vulnerable file.

      secured_input = [
        auth_data,
        iv,
        cipher_text,
        BinData::Uint64be.new(auth_data.length * 8).to_binary_s
      ].join
      expected_authentication_tag = OpenSSL::HMAC.digest(
        sha_digest, mac_key, secured_input
      )[0, sha_size / 2 / 8]
      unless secure_compare(authentication_tag, expected_authentication_tag)
        raise DecryptionFailed.new('Invalid authentication tag')
      end
    end

    class << self
      def decode_compact_serialized(input, private_key_or_secret, algorithms = nil, encryption_methods = nil, _allow_blank_payload = false)
        unless input.count('.') + 1 == NUM_OF_SEGMENTS
          raise InvalidFormat.new("Invalid JWE Format. JWE should include #{NUM_OF_SEGMENTS} segments.")
        end
        jwe = new
        _header_json_, jwe.jwe_encrypted_key, jwe.iv, jwe.cipher_text, jwe.authentication_tag = input.split('.').collect do |segment|
          begin
            Base64.urlsafe_decode64 segment
          rescue ArgumentError
            raise DecryptionFailed
          end
        end
        jwe.auth_data = input.split('.').first
        jwe.header = JSON.parse(_header_json_).with_indifferent_access
        unless private_key_or_secret == :skip_decryption
          jwe.decrypt! private_key_or_secret, algorithms, encryption_methods
        end
        jwe
      end

      def decode_json_serialized(input, private_key_or_secret, algorithms = nil, encryption_methods = nil, _allow_blank_payload = false)
        input = input.with_indifferent_access
        jwe_encrypted_key = if input[:recipients].present?
          input[:recipients].first[:encrypted_key]
        else
          input[:encrypted_key]
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -254,7 +254,7 @@
           raise InvalidFormat.new("Invalid JWE Format. JWE should include #{NUM_OF_SEGMENTS} segments.")
         end
         jwe = new
-        _header_json_, jwe.jwe_encrypted_key, jwe.iv, jwe.cipher_text, jwe.authentication_tag = input.split('.').collect do |segment|
+        _header_json_, jwe.jwe_encrypted_key, jwe.iv, jwe.cipher_text, jwe.authentication_tag = input.split('.', NUM_OF_SEGMENTS).collect do |segment|
           begin
             Base64.urlsafe_decode64 segment
           rescue ArgumentError
```
