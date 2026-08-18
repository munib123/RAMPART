# CrossVul Fix Pair: Improper Input Validation in ruby
**Pair ID:** 3042_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3042_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```ruby
Lines 125-165 of the vulnerable file.


      # Checks if the attached public key needs to be stored locally
      # Overwriting is disabled by default
      # - The publickey_directory config option needs to be set before
      #   the file will be written.
      # - The directory must exist before writing.
      # - The learn_public_keys configuration option must be enabled.
      def write_key_to_disk(key, identity)

        # Writing is disabled. Don't bother checking any other states.
        return unless lookup_config_option('learn_public_keys') =~ /^1|y/

        publickey_dir = lookup_config_option('publickey_dir')

        unless publickey_dir
          Log.info("Public key sent with request but no publickey_dir defined in configuration. Not writing key to disk.")
          return
        end

        if File.directory?(publickey_dir)
          if File.exists?(old_keyfile = File.join(publickey_dir, "#{identity}_pub.pem"))
            old_key = File.read(old_keyfile).chomp

            unless old_key == key
              unless lookup_config_option('overwrite_stored_keys', 'n') =~ /^1|y/
                Log.warn("Public key sent from '%s' does not match the stored key. Not overwriting." % identity)
              else
                Log.warn("Public key sent from '%s' does not match the stored key. Overwriting." % identity)
                File.open(File.join(publickey_dir, "#{identity}_pub.pem"), 'w') { |f| f.puts key }
              end
            end
          else
            Log.debug("Discovered a new public key for '%s'. Writing to '%s'" % [identity, publickey_dir])
            File.open(File.join(publickey_dir, "#{identity}_pub.pem"), 'w') { |f| f.puts key }
          end
        else
          raise("Cannot write public key to '%s'. Directory does not exist." % publickey_dir)
        end
      end

      # Fetches the correct configuration option for a client or a server
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -142,7 +142,14 @@
         end
 
         if File.directory?(publickey_dir)
-          if File.exists?(old_keyfile = File.join(publickey_dir, "#{identity}_pub.pem"))
+          # Reject identity if it would result in directory traversal.
+          old_keyfile = File.join(File.expand_path(publickey_dir), "#{identity}_pub.pem")
+          unless File.expand_path(old_keyfile) == old_keyfile
+            Log.warn("Identity returned by server would result in directory traversal. Not writing key to disk.")
+            return
+          end
+
+          if File.exists?(old_keyfile)
             old_key = File.read(old_keyfile).chomp
 
             unless old_key == key
@@ -150,12 +157,12 @@
                 Log.warn("Public key sent from '%s' does not match the stored key. Not overwriting." % identity)
               else
                 Log.warn("Public key sent from '%s' does not match the stored key. Overwriting." % identity)
-                File.open(File.join(publickey_dir, "#{identity}_pub.pem"), 'w') { |f| f.puts key }
+                File.open(old_keyfile, 'w') { |f| f.puts key }
               end
             end
           else
             Log.debug("Discovered a new public key for '%s'. Writing to '%s'" % [identity, publickey_dir])
-            File.open(File.join(publickey_dir, "#{identity}_pub.pem"), 'w') { |f| f.puts key }
+            File.open(old_keyfile, 'w') { |f| f.puts key }
           end
         else
           raise("Cannot write public key to '%s'. Directory does not exist." % publickey_dir)
```
