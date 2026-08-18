# CrossVul Fix Pair: Improper Input Validation in ruby
**Pair ID:** 3644_6
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3644_6`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```ruby
Lines 106-144 of the vulnerable file.

      Mail.defaults do
        delivery_method :sendmail
      end

      mail = Mail.new do
        to 'to@test.lindsaar.net'
        from '"from+suffix test"@test.lindsaar.net'
        subject 'Can\'t set the return-path'
        message_id '<1234@test.lindsaar.net>'
        body 'body'
      end

      Mail::Sendmail.should_receive(:call).with('/usr/sbin/sendmail',
                                                '-i -t -f "\"from+suffix test\"@test.lindsaar.net"',
                                                'to@test.lindsaar.net',
                                                mail)
      mail.deliver
    end
  end


  it "should still send an email if the settings have been set to nil" do
    Mail.defaults do
      delivery_method :sendmail, :arguments => nil
    end
    
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
end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -123,7 +123,6 @@
     end
   end
 
-
   it "should still send an email if the settings have been set to nil" do
     Mail.defaults do
       delivery_method :sendmail, :arguments => nil
@@ -141,4 +140,22 @@
                                               mail)
     mail.deliver!
   end
+
+  it "should escape evil haxxor attemptes" do
+    Mail.defaults do
+      delivery_method :sendmail, :arguments => nil
+    end
+    
+    mail = Mail.new do
+      from    '"foo\";touch /tmp/PWNED;\""@blah.com'
+      to      'marcel@test.lindsaar.net'
+      subject 'invalid RFC2822'
+    end
+    
+    Mail::Sendmail.should_receive(:call).with('/usr/sbin/sendmail', 
+                                              "-f \"\\\"foo\\\\\\\"\\;touch /tmp/PWNED\\;\\\\\\\"\\\"@blah.com\"", 
+                                              'marcel@test.lindsaar.net', 
+                                              mail)
+    mail.deliver!
+  end
 end
```
