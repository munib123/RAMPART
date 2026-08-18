# CrossVul Fix Pair: Improper Input Validation in ruby
**Pair ID:** 3042_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3042_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```ruby
Lines 263-303 of the vulnerable file.

        end
      end

      describe '#write_key_to_disk' do
        it 'should return if storing public keys is not enabled' do
          @plugin.stubs(:lookup_config_option).with('learn_public_keys').returns(nil)
          File.expects(:dictory?).never
          @plugin.send(:write_key_to_disk, '', '')
        end

        it 'should fail if publicikey_dir does not exist' do
          @plugin.stubs(:lookup_config_option).with('learn_public_keys').returns('1')
          @plugin.stubs(:lookup_config_option).with('publickey_dir').returns('ssh/pkd')
          File.stubs(:directory?).with('ssh/pkd').returns(false)

          expect{
            @plugin.send(:write_key_to_disk, '', '')
          }.to raise_error
        end

        it 'should write the public key to disk if its the first time its been seen' do
          @plugin.stubs(:lookup_config_option).with('learn_public_keys').returns('1')
          @plugin.stubs(:lookup_config_option).with('publickey_dir').returns('ssh/pkd')
          File.stubs(:directory?).with('ssh/pkd').returns(true)
          File.stubs(:exists?).with('ssh/pkd/rspec_pub.pem').returns(false)
          file = mock
          File.expects(:open).with('ssh/pkd/rspec_pub.pem', 'w').yields(file)
          file.expects(:puts).with('ssh-rsa abcd')
          @plugin.send(:write_key_to_disk, 'ssh-rsa abcd', 'rspec')
        end

        it 'should not overwrite an existing file if overwrite_stored_key is not set' do
          @plugin.stubs(:lookup_config_option).with('learn_public_keys').returns('1')
          @plugin.stubs(:lookup_config_option).with('publickey_dir').returns('ssh/pkd')
          @plugin.stubs(:lookup_config_option).with('overwrite_stored_keys', 'n').returns('n')
          File.stubs(:directory?).with('ssh/pkd').returns(true)
          File.stubs(:exists?).with('ssh/pkd/rspec_pub.pem').returns(true)
          File.stubs(:read).with('ssh/pkd/rspec_pub.pem').returns('ssh-rsa dcba')
          Log.expects(:warn)
          File.expects(:open).never
          @plugin.send(:write_key_to_disk, 'ssh-rsa abcd', 'rspec')
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -280,13 +280,23 @@
           }.to raise_error
         end
 
+        it 'should fail if identity would result in directory traversal' do
+          @plugin.stubs(:lookup_config_option).with('learn_public_keys').returns('1')
+          @plugin.stubs(:lookup_config_option).with('publickey_dir').returns('ssh/pkd')
+          File.stubs(:directory?).with('ssh/pkd').returns(true)
+          Log.expects(:warn)
+          File.expects(:open).never
+          @plugin.send(:write_key_to_disk, 'ssh-rsa abcd', '../test')
+        end
+
         it 'should write the public key to disk if its the first time its been seen' do
           @plugin.stubs(:lookup_config_option).with('learn_public_keys').returns('1')
           @plugin.stubs(:lookup_config_option).with('publickey_dir').returns('ssh/pkd')
           File.stubs(:directory?).with('ssh/pkd').returns(true)
-          File.stubs(:exists?).with('ssh/pkd/rspec_pub.pem').returns(false)
+          full_path = File.join(File.expand_path('ssh/pkd'), 'rspec_pub.pem')
+          File.stubs(:exists?).with(full_path).returns(false)
           file = mock
-          File.expects(:open).with('ssh/pkd/rspec_pub.pem', 'w').yields(file)
+          File.expects(:open).with(full_path, 'w').yields(file)
           file.expects(:puts).with('ssh-rsa abcd')
           @plugin.send(:write_key_to_disk, 'ssh-rsa abcd', 'rspec')
         end
@@ -296,8 +306,9 @@
           @plugin.stubs(:lookup_config_option).with('publickey_dir').returns('ssh/pkd')
           @plugin.stubs(:lookup_config_option).with('overwrite_stored_keys', 'n').returns('n')
           File.stubs(:directory?).with('ssh/pkd').returns(true)
-          File.stubs(:exists?).with('ssh/pkd/rspec_pub.pem').returns(true)
-          File.stubs(:read).with('ssh/pkd/rspec_pub.pem').returns('ssh-rsa dcba')
+          full_path = File.join(File.expand_path('ssh/pkd'), 'rspec_pub.pem')
+          File.stubs(:exists?).with(full_path).returns(true)
+          File.stubs(:read).with(full_path).returns('ssh-rsa dcba')
           Log.expects(:warn)
           File.expects(:open).never
           @plugin.send(:write_key_to_disk, 'ssh-rsa abcd', 'rspec')
@@ -308,10 +319,11 @@
           @plugin.stubs(:lookup_config_option).with('publickey_dir').returns('ssh/pkd')
           @plugin.stubs(:lookup_config_option).with('overwrite_stored_keys', 'n').returns('1')
           File.stubs(:directory?).with('ssh/pkd').returns(true)
-          File.stubs(:exists?).with('ssh/pkd/rspec_pub.pem').returns(true)
-          File.stubs(:read).with('ssh/pkd/rspec_pub.pem').returns('ssh-rsa dcba')
+          full_path = File.join(File.expand_path('ssh/pkd'), 'rspec_pub.pem')
+          File.stubs(:exists?).with(full_path).returns(true)
+          File.stubs(:read).with(full_path).returns('ssh-rsa dcba')
           file = mock
-          File.expects(:open).with('ssh/pkd/rspec_pub.pem', 'w').yields(file)
+          File.expects(:open).with(full_path, 'w').yields(file)
           file.expects(:puts).with('ssh-rsa abcd')
           Log.expects(:warn)
           @plugin.send(:write_key_to_disk, 'ssh-rsa abcd', 'rspec')
```
