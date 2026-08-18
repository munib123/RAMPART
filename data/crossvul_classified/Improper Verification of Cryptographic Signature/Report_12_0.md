# CrossVul Fix Pair: Improper Verification of Cryptographic Signature in ruby
**Pair ID:** 12_0
**Vulnerability Class:** Improper Verification of Cryptographic Signature
**CWE:** CWE-347
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `12_0`)

## Vulnerability Information & PoC

## Description
Improper Verification of Cryptographic Signature - The product does not verify, or incorrectly verifies, the cryptographic signature for data.

## Vulnerable Code
```ruby
Lines 586-626 of the vulnerable file.

              "#{e.message} (#{e.class})"
    raise Gem::Package::FormatError.new message, @gem
  end

  ##
  # Verifies the files of the +gem+

  def verify_files gem
    gem.each do |entry|
      verify_entry entry
    end

    unless @spec then
      raise Gem::Package::FormatError.new 'package metadata is missing', @gem
    end

    unless @files.include? 'data.tar.gz' then
      raise Gem::Package::FormatError.new \
              'package content (data.tar.gz) is missing', @gem
    end
  end

  ##
  # Verifies that +entry+ is a valid gzipped file.

  def verify_gz entry # :nodoc:
    Zlib::GzipReader.wrap entry do |gzio|
      gzio.read 16384 until gzio.eof? # gzip checksum verification
    end
  rescue Zlib::GzipFile::Error => e
    raise Gem::Package::FormatError.new(e.message, entry.full_name)
  end

end

require 'rubygems/package/digest_io'
require 'rubygems/package/source'
require 'rubygems/package/file_source'
require 'rubygems/package/io_source'
require 'rubygems/package/old'
require 'rubygems/package/tar_header'
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -603,6 +603,10 @@
       raise Gem::Package::FormatError.new \
               'package content (data.tar.gz) is missing', @gem
     end
+
+    if duplicates = @files.group_by {|f| f }.select {|k,v| v.size > 1 }.map(&:first) and duplicates.any?
+      raise Gem::Security::Exception, "duplicate files in the package: (#{duplicates.map(&:inspect).join(', ')})"
+    end
   end
 
   ##
```
