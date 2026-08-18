# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in ruby
**Pair ID:** 3642_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3642_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```ruby
Lines 1-29 of the vulnerable file.

module Mail
  
  # FileDelivery class delivers emails into multiple files based on the destination
  # address.  Each file is appended to if it already exists.
  # 
  # So if you have an email going to fred@test, bob@test, joe@anothertest, and you
  # set your location path to /path/to/mails then FileDelivery will create the directory
  # if it does not exist, and put one copy of the email in three files, called
  # "fred@test", "bob@test" and "joe@anothertest"
  # 
  # Make sure the path you specify with :location is writable by the Ruby process
  # running Mail.
  class FileDelivery

    if RUBY_VERSION >= '1.9.1'
      require 'fileutils'
    else
      require 'ftools'
    end

    def initialize(values)
      self.settings = { :location => './mails' }.merge!(values)
    end
    
    attr_accessor :settings
    
    def deliver!(mail)
      if ::File.respond_to?(:makedirs)
        ::File.makedirs settings[:location]
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -6,7 +6,7 @@
   # So if you have an email going to fred@test, bob@test, joe@anothertest, and you
   # set your location path to /path/to/mails then FileDelivery will create the directory
   # if it does not exist, and put one copy of the email in three files, called
-  # "fred@test", "bob@test" and "joe@anothertest"
+  # by their message id
   # 
   # Make sure the path you specify with :location is writable by the Ruby process
   # running Mail.
@@ -32,7 +32,7 @@
       end
 
       mail.destinations.uniq.each do |to|
-        ::File.open(::File.join(settings[:location], to), 'a') { |f| "#{f.write(mail.encoded)}\r\n\r\n" }
+        ::File.open(::File.join(settings[:location], File.basename(to.to_s)), 'a') { |f| "#{f.write(mail.encoded)}\r\n\r\n" }
       end
     end
     
```
