# CrossVul Fix Pair: Improper Input Validation in ruby
**Pair ID:** 3643_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3643_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```ruby
Lines 131-161 of the vulnerable file.

    mail = Mail.new do
      from    'from@test.lindsaar.net'
      to      'marcel@test.lindsaar.net, bob@test.lindsaar.net'
      subject 'invalid RFC2822'
    end
    
    Mail::Sendmail.should_receive(:call).with('/usr/sbin/sendmail', 
                                              '-f "from@test.lindsaar.net"', 
                                              'marcel@test.lindsaar.net bob@test.lindsaar.net', 
                                              mail)
    mail.deliver!
  end

  it "should escape evil haxxor attemptes" do
    Mail.defaults do
      delivery_method :sendmail, :arguments => nil
    end
    
    mail = Mail.new do
      from    '"foo\";touch /tmp/PWNED;\""@blah.com'
      to      'marcel@test.lindsaar.net'
      subject 'invalid RFC2822'
    end
    
    Mail::Sendmail.should_receive(:call).with('/usr/sbin/sendmail', 
                                              "-f \"\\\"foo\\\\\\\"\\;touch /tmp/PWNED\\;\\\\\\\"\\\"@blah.com\"", 
                                              'marcel@test.lindsaar.net', 
                                              mail)
    mail.deliver!
  end
end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -148,13 +148,13 @@
     
     mail = Mail.new do
       from    '"foo\";touch /tmp/PWNED;\""@blah.com'
-      to      'marcel@test.lindsaar.net'
+      to      '"foo\";touch /tmp/PWNED;\""@blah.com'
       subject 'invalid RFC2822'
     end
     
     Mail::Sendmail.should_receive(:call).with('/usr/sbin/sendmail', 
                                               "-f \"\\\"foo\\\\\\\"\\;touch /tmp/PWNED\\;\\\\\\\"\\\"@blah.com\"", 
-                                              'marcel@test.lindsaar.net', 
+                                              "\\\"foo\\\\\\\"\\;touch /tmp/PWNED\\;\\\\\\\"\\\"@blah.com", 
                                               mail)
     mail.deliver!
   end
```
