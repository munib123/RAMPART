# CrossVul Fix Pair: Use of Password Hash With Insufficient Computational Effort in ruby
**Pair ID:** 2025_0
**Vulnerability Class:** Weak Cryptography for Passwords
**CWE:** CWE-916
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2025_0`)

## Vulnerability Information & PoC

## Description
Use of Password Hash With Insufficient Computational Effort - Many password storage mechanisms compute a hash and store the hash, instead of storing the original password in plaintext.

## Vulnerable Code
```ruby
Lines 10-38 of the vulnerable file.

    # Pass a hash type as a symbol (:md5, :sha, :ssha) and a plaintext
    # password. This function will return a hashed representation.
    #
    #--
    # STUB: This is here to fulfill the requirements of an RFC, which
    # one?
    #
    # TODO:
    # * maybe salted-md5
    # * Should we provide sha1 as a synonym for sha1? I vote no because then
    #   should you also provide ssha1 for symmetry?
    #
    attribute_value = ""
    def generate(type, str)
      case type
      when :md5
         attribute_value = '{MD5}' + Base64.encode64(Digest::MD5.digest(str)).chomp! 
      when :sha
         attribute_value = '{SHA}' + Base64.encode64(Digest::SHA1.digest(str)).chomp! 
      when :ssha
         srand; salt = (rand * 1000).to_i.to_s 
         attribute_value = '{SSHA}' + Base64.encode64(Digest::SHA1.digest(str + salt) + salt).chomp!
      else
         raise Net::LDAP::HashTypeUnsupportedError, "Unsupported password-hash type (#{type})"
      end
      return attribute_value
    end
  end
end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -27,7 +27,7 @@
       when :sha
          attribute_value = '{SHA}' + Base64.encode64(Digest::SHA1.digest(str)).chomp! 
       when :ssha
-         srand; salt = (rand * 1000).to_i.to_s 
+         srand; salt = SecureRandom.random_bytes(16)
          attribute_value = '{SSHA}' + Base64.encode64(Digest::SHA1.digest(str + salt) + salt).chomp!
       else
          raise Net::LDAP::HashTypeUnsupportedError, "Unsupported password-hash type (#{type})"
```
