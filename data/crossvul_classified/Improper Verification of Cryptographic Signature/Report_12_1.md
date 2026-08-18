# CrossVul Fix Pair: Improper Verification of Cryptographic Signature in ruby
**Pair ID:** 12_1
**Vulnerability Class:** Improper Verification of Cryptographic Signature
**CWE:** CWE-347
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `12_1`)

## Vulnerability Information & PoC

## Description
Improper Verification of Cryptographic Signature - The product does not verify, or incorrectly verifies, the cryptographic signature for data.

## Vulnerable Code
```ruby
Lines 179-219 of the vulnerable file.

      signer.digest_algorithm,
      Digest::SHA512,
    ].compact.uniq

    digests = add_file_digest name, mode, digest_algorithms do |io|
      yield io
    end

    signature_digest = digests.values.compact.find do |digest|
      digest_name =
        if digest.respond_to? :name then
          digest.name
        else
          /::([^:]+)$/ =~ digest.class.name
          $1
        end

      digest_name == signer.digest_name
    end

    if signer.key then
      signature = signer.sign signature_digest.digest

      add_file_simple "#{name}.sig", 0444, signature.length do |io|
        io.write signature
      end
    end

    digests
  end

  ##
  # Add file +name+ with permissions +mode+ +size+ bytes long.  Yields an IO
  # to write the file to.

  def add_file_simple(name, mode, size) # :yields: io
    check_closed

    name, prefix = split_name name

    header = Gem::Package::TarHeader.new(:name => name, :mode => mode,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -196,6 +196,8 @@
       digest_name == signer.digest_name
     end
 
+    raise "no #{signer.digest_name} in #{digests.values.compact}" unless signature_digest
+
     if signer.key then
       signature = signer.sign signature_digest.digest
 
```
