# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in ruby
**Pair ID:** 5751_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5751_0`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```ruby
Lines 96-136 of the vulnerable file.

   content_type: the content-type of the attachment
       filename: the filename of the attachment as saved to disk
Return value:
  True if the viewing was successful, false otherwise. If false, calling
  /usr/bin/run-mailcap will be tried.
EOS
#' stupid ruby-mode

    ## raw_content is the post-MIME-decode content. this is used for
    ## saving the attachment to disk.
    attr_reader :content_type, :filename, :lines, :raw_content
    bool_reader :quotable

    ## store tempfile objects as class variables so that they
    ## are not removed when the viewing process returns. they
    ## should be garbage collected when the class variable is removed.
    @@view_tempfiles = []

    def initialize content_type, filename, encoded_content, sibling_types
      @content_type = content_type.downcase
      @filename = filename
      @quotable = false # changed to true if we can parse it through the
                        # mime-decode hook, or if it's plain text
      @raw_content =
        if encoded_content.body
          encoded_content.decode
        else
          "For some bizarre reason, RubyMail was unable to parse this attachment.\n"
        end

      text = case @content_type
      when /^text\/plain\b/
        @raw_content
      else
        ## please see note in write_to_disk on important usage
        ## of quotes to avoid remote command injection.
        HookManager.run "mime-decode", :content_type => content_type,
                        :filename => lambda { write_to_disk },
                        :charset => encoded_content.charset,
                        :sibling_types => sibling_types
      end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -113,6 +113,11 @@
 
     def initialize content_type, filename, encoded_content, sibling_types
       @content_type = content_type.downcase
+      if Shellwords.escape(@content_type) != @content_type
+        warn "content_type #{@content_type} is not safe, changed to application/octet-stream"
+        @content_type = 'application/octet-stream'
+      end
+
       @filename = filename
       @quotable = false # changed to true if we can parse it through the
                         # mime-decode hook, or if it's plain text
@@ -129,7 +134,7 @@
       else
         ## please see note in write_to_disk on important usage
         ## of quotes to avoid remote command injection.
-        HookManager.run "mime-decode", :content_type => content_type,
+        HookManager.run "mime-decode", :content_type => @content_type,
                         :filename => lambda { write_to_disk },
                         :charset => encoded_content.charset,
                         :sibling_types => sibling_types
@@ -189,7 +194,7 @@
     ## note that the path returned from write_to_disk is
     ## Shellwords.escaped and is intended to be used without single
     ## or double quotes. the use of either opens sup up for remote
-    ## code injection in the file name.
+    ## code injection through the file name.
     def write_to_disk
       begin
         file = Tempfile.new(["sup", Shellwords.escape(@filename.gsub("/", "_")) || "sup-attachment"])
```
