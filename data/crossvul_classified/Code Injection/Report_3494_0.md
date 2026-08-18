# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in ruby
**Pair ID:** 3494_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3494_0`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```ruby
Lines 47-87 of the vulnerable file.

      @block = nil

      @body = "",
      @session = []
      @assigns = []
    end

    def location; headers['Location'] end
    def location=(url) headers['Location'] = url end


    # Sets the HTTP response's content MIME type. For example, in the controller
    # you could write this:
    #
    #  response.content_type = "text/plain"
    #
    # If a character set has been defined for this response (see charset=) then
    # the character set information will also be included in the content type
    # information.
    def content_type=(mime_type)
      self.headers["Content-Type"] =
        if mime_type =~ /charset/ || (c = charset).nil?
          mime_type.to_s
        else
          "#{mime_type}; charset=#{c}"
        end
    end

    # Returns the response's content MIME type, or nil if content type has been set.
    def content_type
      content_type = String(headers["Content-Type"] || headers["type"]).split(";")[0]
      content_type.blank? ? nil : content_type
    end

    # Set the charset of the Content-Type header. Set to nil to remove it.
    # If no content type is set, it defaults to HTML.
    def charset=(charset)
      headers["Content-Type"] =
        if charset
          "#{content_type || Mime::HTML}; charset=#{charset}"
        else
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -64,12 +64,13 @@
     # the character set information will also be included in the content type
     # information.
     def content_type=(mime_type)
-      self.headers["Content-Type"] =
+      new_content_type =
         if mime_type =~ /charset/ || (c = charset).nil?
           mime_type.to_s
         else
           "#{mime_type}; charset=#{c}"
         end
+      self.headers["Content-Type"] = URI.escape(new_content_type, "\r\n")
     end
 
     # Returns the response's content MIME type, or nil if content type has been set.
```
