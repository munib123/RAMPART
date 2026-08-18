# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in ruby
**Pair ID:** 1550_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1550_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```ruby
Lines 1-24 of the vulnerable file.

module Paperclip
  class MediaTypeSpoofDetector
    def self.using(file, name)
      new(file, name)
    end

    def initialize(file, name)
      @file = file
      @name = name
    end

    def spoofed?
      if has_name? && has_extension? && media_type_mismatch? && mapping_override_mismatch?
        Paperclip.log("Content Type Spoof: Filename #{File.basename(@name)} (#{supplied_file_content_types}), content type discovered from file command: #{calculated_content_type}. See documentation to allow this combination.")
        true
      end
    end

    private

    def has_name?
      @name.present?
    end

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,18 +1,21 @@
 module Paperclip
   class MediaTypeSpoofDetector
-    def self.using(file, name)
-      new(file, name)
+    def self.using(file, name, content_type)
+      new(file, name, content_type)
     end
 
-    def initialize(file, name)
+    def initialize(file, name, content_type)
       @file = file
       @name = name
+      @content_type = content_type || ""
     end
 
     def spoofed?
       if has_name? && has_extension? && media_type_mismatch? && mapping_override_mismatch?
-        Paperclip.log("Content Type Spoof: Filename #{File.basename(@name)} (#{supplied_file_content_types}), content type discovered from file command: #{calculated_content_type}. See documentation to allow this combination.")
+        Paperclip.log("Content Type Spoof: Filename #{File.basename(@name)} (#{supplied_content_type} from Headers, #{content_types_from_name} from Extension), content type discovered from file command: #{calculated_content_type}. See documentation to allow this combination.")
         true
+      else
+        false
       end
     end
 
@@ -27,27 +30,52 @@
     end
 
     def media_type_mismatch?
-      ! supplied_file_media_types.include?(calculated_media_type)
+      supplied_type_mismatch? || calculated_type_mismatch?
+    end
+
+    def supplied_type_mismatch?
+      supplied_media_type.present? && !media_types_from_name.include?(supplied_media_type)
+    end
+
+    def calculated_type_mismatch?
+      !media_types_from_name.include?(calculated_media_type)
     end
 
     def mapping_override_mismatch?
       mapped_content_type != calculated_content_type
     end
 
-    def supplied_file_media_types
-      @supplied_file_media_types ||= MIME::Types.type_for(@name).collect(&:media_type)
+
+    def supplied_content_type
+      @content_type
+    end
+
+    def supplied_media_type
+      @content_type.split("/").first
+    end
+
+    def content_types_from_name
+      @content_types_from_name ||= MIME::Types.type_for(@name)
+    end
+
+    def media_types_from_name
+      @media_types_from_name ||= content_types_from_name.collect(&:media_type)
+    end
+
+    def calculated_content_type
+      @calculated_content_type ||= type_from_file_command.chomp
     end
 
     def calculated_media_type
       @calculated_media_type ||= calculated_content_type.split("/").first
     end
 
-    def supplied_file_content_types
-      @supplied_file_content_types ||= MIME::Types.type_for(@name).collect(&:content_type)
-    end
-
-    def calculated_content_type
-      @calculated_content_type ||= type_from_file_command.chomp
+    def type_from_file_command
+      begin
+        Paperclip.run("file", "-b --mime :file", :file => @file.path).split(/[:;]\s+/).first
+      rescue Cocaine::CommandLineError
+        ""
+      end
     end
 
     def mapped_content_type
@@ -57,13 +85,5 @@
     def filename_extension
       File.extname(@name.to_s.downcase).sub(/^\./, '').to_sym
     end
-
-    def type_from_file_command
-      begin
-        Paperclip.run("file", "-b --mime :file", :file => @file.path).split(/[:;]\s+/).first
-      rescue Cocaine::CommandLineError
-        ""
-      end
-    end
   end
 end
```
