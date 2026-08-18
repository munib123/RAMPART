# CrossVul Fix Pair: Improper Input Validation in ruby
**Pair ID:** 1220_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1220_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```ruby
Lines 162-202 of the vulnerable file.

      key.check_key
    end

    def raw_to_asn1(signature, public_key)
      byte_size = (public_key.group.degree + 7) / 8
      r = signature[0..(byte_size - 1)]
      s = signature[byte_size..-1]
      OpenSSL::ASN1::Sequence.new([r, s].map { |int| OpenSSL::ASN1::Integer.new(OpenSSL::BN.new(int, 2)) }).to_der
    end

    def asn1_to_raw(signature, private_key)
      byte_size = (private_key.group.degree + 7) / 8
      OpenSSL::ASN1.decode(signature).value.map { |value| value.value.to_s(2).rjust(byte_size, "\x00") }.join
    end

    class << self
      def decode_compact_serialized(input, public_key_or_secret, algorithms = nil, allow_blank_payload = false)
        unless input.count('.') + 1 == NUM_OF_SEGMENTS
          raise InvalidFormat.new("Invalid JWS Format. JWS should include #{NUM_OF_SEGMENTS} segments.")
        end
        header, claims, signature = input.split('.', JWS::NUM_OF_SEGMENTS).collect do |segment|
          Base64.urlsafe_decode64 segment.to_s
        end
        header = JSON.parse(header).with_indifferent_access
        if allow_blank_payload && claims == ''
          claims = nil
        else
          claims = JSON.parse(claims).with_indifferent_access
        end
        jws = new claims
        jws.header = header
        jws.signature = signature
        jws.signature_base_string = input.split('.')[0, JWS::NUM_OF_SEGMENTS - 1].join('.')
        jws.verify! public_key_or_secret, algorithms unless public_key_or_secret == :skip_verification
        jws
      end

      def decode_json_serialized(input, public_key_or_secret, algorithms = nil, allow_blank_payload = false)
        input = input.with_indifferent_access
        header, payload, signature = if input[:signatures].present?
          [
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -179,7 +179,7 @@
         unless input.count('.') + 1 == NUM_OF_SEGMENTS
           raise InvalidFormat.new("Invalid JWS Format. JWS should include #{NUM_OF_SEGMENTS} segments.")
         end
-        header, claims, signature = input.split('.', JWS::NUM_OF_SEGMENTS).collect do |segment|
+        header, claims, signature = input.split('.', NUM_OF_SEGMENTS).collect do |segment|
           Base64.urlsafe_decode64 segment.to_s
         end
         header = JSON.parse(header).with_indifferent_access
@@ -191,7 +191,7 @@
         jws = new claims
         jws.header = header
         jws.signature = signature
-        jws.signature_base_string = input.split('.')[0, JWS::NUM_OF_SEGMENTS - 1].join('.')
+        jws.signature_base_string = input.split('.')[0, NUM_OF_SEGMENTS - 1].join('.')
         jws.verify! public_key_or_secret, algorithms unless public_key_or_secret == :skip_verification
         jws
       end
```
