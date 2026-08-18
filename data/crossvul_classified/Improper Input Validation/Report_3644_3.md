# CrossVul Fix Pair: Improper Input Validation in ruby
**Pair ID:** 3644_3
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3644_3`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```ruby
Lines 1-20 of the vulnerable file.

module Mail

  class Exim < Sendmail

    def deliver!(mail)
      envelope_from = mail.return_path || mail.sender || mail.from_addrs.first
      return_path = "-f \"#{envelope_from.to_s.shellescape}\"" if envelope_from
      arguments = [settings[:arguments], return_path].compact.join(" ")
      self.class.call(settings[:location], arguments, mail)
    end

    def self.call(path, arguments, mail)
      IO.popen("#{path} #{arguments}", "w+") do |io|
        io.puts mail.encoded.to_lf
        io.flush
      end
    end

  end
end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,12 +1,45 @@
 module Mail
 
+  # A delivery method implementation which sends via exim.
+  #
+  # To use this, first find out where the exim binary is on your computer,
+  # if you are on a mac or unix box, it is usually in /usr/sbin/exim, this will
+  # be your exim location.
+  #
+  #   Mail.defaults do
+  #     delivery_method :exim
+  #   end
+  #
+  # Or if your exim binary is not at '/usr/sbin/exim'
+  #
+  #   Mail.defaults do
+  #     delivery_method :exim, :location => '/absolute/path/to/your/exim'
+  #   end
+  #
+  # Then just deliver the email as normal:
+  #
+  #   Mail.deliver do
+  #     to 'mikel@test.lindsaar.net'
+  #     from 'ada@test.lindsaar.net'
+  #     subject 'testing exim'
+  #     body 'testing exim'
+  #   end
+  #
+  # Or by calling deliver on a Mail message
+  #
+  #   mail = Mail.new do
+  #     to 'mikel@test.lindsaar.net'
+  #     from 'ada@test.lindsaar.net'
+  #     subject 'testing exim'
+  #     body 'testing exim'
+  #   end
+  #
+  #   mail.deliver!
   class Exim < Sendmail
 
-    def deliver!(mail)
-      envelope_from = mail.return_path || mail.sender || mail.from_addrs.first
-      return_path = "-f \"#{envelope_from.to_s.shellescape}\"" if envelope_from
-      arguments = [settings[:arguments], return_path].compact.join(" ")
-      self.class.call(settings[:location], arguments, mail)
+    def initialize(values)
+      self.settings = { :location       => '/usr/sbin/exim',
+                        :arguments      => '-i -t' }.merge(values)
     end
 
     def self.call(path, arguments, mail)
```
