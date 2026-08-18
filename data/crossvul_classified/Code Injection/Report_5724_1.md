# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in ruby
**Pair ID:** 5724_1
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5724_1`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```ruby
Lines 1-22 of the vulnerable file.

require 'tempfile'

module Rgpg
  module GpgHelper
    def self.generate_key_pair(key_base_name, recipient, real_name)
      public_key_file_name = "#{key_base_name}.pub"
      private_key_file_name = "#{key_base_name}.sec"
      script = generate_key_script(public_key_file_name, private_key_file_name, recipient, real_name)
      script_file = Tempfile.new('gpg-script')
      begin
        script_file.write(script)
        script_file.close
        result = system("gpg --batch --gen-key #{script_file.path}")
        raise RuntimeError.new('gpg failed') unless result
      ensure
        script_file.close
        script_file.unlink
      end
    end

    def self.encrypt_file(public_key_file_name, input_file_name, output_file_name)
      raise ArgumentError.new("Public key file \"#{public_key_file_name}\" does not exist") unless File.exist?(public_key_file_name)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,4 +1,5 @@
 require 'tempfile'
+require 'shellwords'
 
 module Rgpg
   module GpgHelper
@@ -10,7 +11,7 @@
       begin
         script_file.write(script)
         script_file.close
-        result = system("gpg --batch --gen-key #{script_file.path}")
+        result = system("gpg --batch --gen-key #{Shellwords.escape(script_file.path)}")
         raise RuntimeError.new('gpg failed') unless result
       ensure
         script_file.close
@@ -62,12 +63,12 @@
         'gpg',
         '--no-default-keyring'
       ] + args
-      command_line = fragments.join(' ')
+      command_line = fragments.collect { |fragment| Shellwords.escape(fragment) }.join(' ')
 
       output_file = Tempfile.new('gpg-output')
       begin
         output_file.close
-        result = system("#{command_line} > #{output_file.path} 2>&1")
+        result = system("#{command_line} > #{Shellwords.escape(output_file.path)} 2>&1")
       ensure
         output_file.unlink
       end
```
