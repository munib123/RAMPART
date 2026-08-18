# CrossVul Fix Pair: Improper Input Validation in ruby
**Pair ID:** 3643_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3643_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```ruby
Lines 32-62 of the vulnerable file.

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
      return_path = "-f " + '"' + envelope_from.escape_for_shell + '"' if envelope_from

      arguments = [settings[:arguments], return_path].compact.join(" ")

      self.class.call(settings[:location], arguments, mail.destinations.collect(&:shellescape).join(" "), mail)
    end

    def self.call(path, arguments, destinations, mail)
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
@@ -49,7 +49,7 @@
 
       arguments = [settings[:arguments], return_path].compact.join(" ")
 
-      self.class.call(settings[:location], arguments, mail.destinations.collect(&:shellescape).join(" "), mail)
+      self.class.call(settings[:location], arguments, mail.destinations.collect(&:escape_for_shell).join(" "), mail)
     end
 
     def self.call(path, arguments, destinations, mail)
```
