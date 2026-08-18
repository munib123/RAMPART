# CrossVul Fix Pair: Deserialization of Untrusted Data in ruby
**Pair ID:** 2500_3
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2500_3`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```ruby
Lines 451-491 of the vulnerable file.


  ##
  # Opens +io+ as a gzipped tar archive

  def open_tar_gz io # :nodoc:
    Zlib::GzipReader.wrap io do |gzio|
      tar = Gem::Package::TarReader.new gzio

      yield tar
    end
  end

  ##
  # Reads and loads checksums.yaml.gz from the tar file +gem+

  def read_checksums gem
    Gem.load_yaml

    @checksums = gem.seek 'checksums.yaml.gz' do |entry|
      Zlib::GzipReader.wrap entry do |gz_io|
        YAML.load gz_io.read
      end
    end
  end

  ##
  # Prepares the gem for signing and checksum generation.  If a signing
  # certificate and key are not present only checksum generation is set up.

  def setup_signer
    passphrase = ENV['GEM_PRIVATE_KEY_PASSPHRASE']
    if @spec.signing_key then
      @signer = Gem::Security::Signer.new @spec.signing_key, @spec.cert_chain, passphrase
      @spec.signing_key = nil
      @spec.cert_chain = @signer.cert_chain.map { |cert| cert.to_s }
    else
      @signer = Gem::Security::Signer.new nil, nil, passphrase
      @spec.cert_chain = @signer.cert_chain.map { |cert| cert.to_pem } if
        @signer.cert_chain
    end
  end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -468,7 +468,7 @@
 
     @checksums = gem.seek 'checksums.yaml.gz' do |entry|
       Zlib::GzipReader.wrap entry do |gz_io|
-        YAML.load gz_io.read
+        Gem::SafeYAML.safe_load gz_io.read
       end
     end
   end
```
