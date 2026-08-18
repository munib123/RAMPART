# CrossVul Fix Pair: Improper Input Validation in ruby
**Pair ID:** 3644_4
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3644_4`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```ruby
Lines 28-62 of the vulnerable file.

  #
  #   mail = Mail.new do
  #     to 'mikel@test.lindsaar.net'
  #     from 'ada@test.lindsaar.net'
  #     subject 'testing sendmail'
  #     body 'testing sendmail'
  #   end
  #
  #   mail.deliver!
  class Sendmail

    def initialize(values)
      self.settings = { :location       => '/usr/sbin/sendmail',
                        :arguments      => '-i -t' }.merge(values)
    end

    attr_accessor :settings

    def deliver!(mail)
      envelope_from = mail.return_path || mail.sender || mail.from_addrs.first
      return_path = "-f \"#{envelope_from.to_s.gsub('"', '\"')}\"" if envelope_from

      arguments = [settings[:arguments], return_path].compact.join(" ")

      Sendmail.call(settings[:location], arguments, mail.destinations.collect(&:shellescape).join(" "), mail)
    end

    def Sendmail.call(path, arguments, destinations, mail)
      IO.popen("#{path} #{arguments} #{destinations}", "w+") do |io|
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
@@ -45,14 +45,14 @@
 
     def deliver!(mail)
       envelope_from = mail.return_path || mail.sender || mail.from_addrs.first
-      return_path = "-f \"#{envelope_from.to_s.gsub('"', '\"')}\"" if envelope_from
+      return_path = "-f " + '"' + envelope_from.escape_for_shell + '"' if envelope_from
 
       arguments = [settings[:arguments], return_path].compact.join(" ")
 
-      Sendmail.call(settings[:location], arguments, mail.destinations.collect(&:shellescape).join(" "), mail)
+      self.class.call(settings[:location], arguments, mail.destinations.collect(&:shellescape).join(" "), mail)
     end
 
-    def Sendmail.call(path, arguments, destinations, mail)
+    def self.call(path, arguments, destinations, mail)
       IO.popen("#{path} #{arguments} #{destinations}", "w+") do |io|
         io.puts mail.encoded.to_lf
         io.flush
```
