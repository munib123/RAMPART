# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in ruby
**Pair ID:** 5750_1
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5750_1`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```ruby
Lines 43-83 of the vulnerable file.

        prefix = prefix_suffix
        suffix = ""
      when Array
        prefix = prefix_suffix[0]
        suffix = prefix_suffix[1]
      else
        raise ArgumentError, "unexpected prefix_suffix: #{prefix_suffix.inspect}"
      end
      t = Time.now.strftime("%Y%m%d")
      path = "#{prefix}#{t}-#{$$}-#{rand(0x100000000).to_s(36)}"
      path << "-#{n}" if n
      path << suffix
    end
  end
end


module Redwood
module Chunk
  class Attachment
    HookManager.register "mime-decode", <<EOS
Decodes a MIME attachment into text form. The text will be displayed
directly in Sup. For attachments that you wish to use a separate program
to view (e.g. images), you should use the mime-view hook instead.

Variables:
   content_type: the content-type of the attachment
        charset: the charset of the attachment, if applicable
       filename: the filename of the attachment as saved to disk
  sibling_types: if this attachment is part of a multipart MIME attachment,
                 an array of content-types for all attachments. Otherwise,
                 the empty array.
Return value:
  The decoded text of the attachment, or nil if not decoded.
EOS

    HookManager.register "mime-view", <<EOS
Views a non-text MIME attachment. This hook allows you to run
third-party programs for attachments that require such a thing (e.g.
images). To instead display a text version of the attachment directly in
Sup, use the mime-decode hook instead.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -60,6 +60,8 @@
 module Redwood
 module Chunk
   class Attachment
+    ## please see note in write_to_disk on important usage
+    ## of quotes to avoid remote command injection.
     HookManager.register "mime-decode", <<EOS
 Decodes a MIME attachment into text form. The text will be displayed
 directly in Sup. For attachments that you wish to use a separate program
@@ -76,6 +78,9 @@
   The decoded text of the attachment, or nil if not decoded.
 EOS
 
+
+    ## please see note in write_to_disk on important usage
+    ## of quotes to avoid remote command injection.
     HookManager.register "mime-view", <<EOS
 Views a non-text MIME attachment. This hook allows you to run
 third-party programs for attachments that require such a thing (e.g.
@@ -122,6 +127,8 @@
       when /^text\/plain\b/
         @raw_content
       else
+        ## please see note in write_to_disk on important usage
+        ## of quotes to avoid remote command injection.
         HookManager.run "mime-decode", :content_type => content_type,
                         :filename => lambda { write_to_disk },
                         :charset => encoded_content.charset,
@@ -153,11 +160,13 @@
     def initial_state; :open end
     def viewable?; @lines.nil? end
     def view_default! path
+      ## please see note in write_to_disk on important usage
+      ## of quotes to avoid remote command injection.
       case RbConfig::CONFIG['arch']
         when /darwin/
-          cmd = "open '#{path}'"
+          cmd = "open #{path}"
         else
-          cmd = "/usr/bin/run-mailcap --action=view '#{@content_type}:#{path}'"
+          cmd = "/usr/bin/run-mailcap --action=view #{@content_type}:#{path}"
       end
       debug "running: #{cmd.inspect}"
       BufferManager.shell_out(cmd)
@@ -165,6 +174,8 @@
     end
 
     def view!
+      ## please see note in write_to_disk on important usage
+      ## of quotes to avoid remote command injection.
       write_to_disk do |file|
 
         @@view_tempfiles.push file # make sure the tempfile is not garbage collected before sup stops
@@ -175,6 +186,10 @@
       end
     end
 
+    ## note that the path returned from write_to_disk is
+    ## Shellwords.escaped and is intended to be used without single
+    ## or double quotes. the use of either opens sup up for remote
+    ## code injection in the file name.
     def write_to_disk
       begin
         file = Tempfile.new(["sup", Shellwords.escape(@filename.gsub("/", "_")) || "sup-attachment"])
@@ -243,7 +258,7 @@
   class EnclosedMessage
     attr_reader :lines
     def initialize from, to, cc, date, subj
-      @from = from ? "unknown sender" : from.full_adress
+      @from = from ? "unknown sender" : from.full_address
       @to = to ? "" : to.map { |p| p.full_address }.join(", ")
       @cc = cc ? "" : cc.map { |p| p.full_address }.join(", ")
       if date
```
