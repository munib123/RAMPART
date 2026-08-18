# CrossVul Fix Pair: Improper Input Validation in php
**Pair ID:** 1785_3
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1785_3`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```php
Lines 344-384 of the vulnerable file.

            'first.last@[12.34.56.78]',
            'first.last@[IPv6:::12.34.56.78]',
            'first.last@[IPv6:1111:2222:3333::4444:12.34.56.78]',
            'first.last@[IPv6:1111:2222:3333:4444:5555:6666:12.34.56.78]',
            'first.last@[IPv6:::1111:2222:3333:4444:5555:6666]',
            'first.last@[IPv6:1111:2222:3333::4444:5555:6666]',
            'first.last@[IPv6:1111:2222:3333:4444:5555:6666::]',
            'first.last@[IPv6:1111:2222:3333:4444:5555:6666:7777:8888]',
            'first.last@x23456789012345678901234567890123456789012345678901234567890123.iana.org',
            'first.last@3com.com',
            'first.last@123.iana.org',
            '"first\last"@iana.org',
            'first.last@[IPv6:1111:2222:3333::4444:5555:12.34.56.78]',
            'first.last@[IPv6:1111:2222:3333::4444:5555:6666:7777]',
            'first.last@example.123',
            'first.last@com',
            '"Abc\@def"@iana.org',
            '"Fred\ Bloggs"@iana.org',
            '"Joe.\Blow"@iana.org',
            '"Abc@def"@iana.org',
            '"Fred Bloggs"@iana.org',
            'user+mailbox@iana.org',
            'customer/department=shipping@iana.org',
            '$A12345@iana.org',
            '!def!xyz%abc@iana.org',
            '_somename@iana.org',
            'dclo@us.ibm.com',
            'peter.piper@iana.org',
            '"Doug \"Ace\" L."@iana.org',
            'test@iana.org',
            'TEST@iana.org',
            '1234567890@iana.org',
            'test+test@iana.org',
            'test-test@iana.org',
            't*est@iana.org',
            '+1~1+@iana.org',
            '{_test_}@iana.org',
            '"[[ test ]]"@iana.org',
            'test.test@iana.org',
            '"test.test"@iana.org',
            'test."test"@iana.org',
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -361,7 +361,6 @@
             '"Fred\ Bloggs"@iana.org',
             '"Joe.\Blow"@iana.org',
             '"Abc@def"@iana.org',
-            '"Fred Bloggs"@iana.org',
             'user+mailbox@iana.org',
             'customer/department=shipping@iana.org',
             '$A12345@iana.org',
@@ -467,7 +466,7 @@
             'first.last@[IPv6:a1::b2:11.22.33.44]',
             'test@test.com',
             'test@xn--example.com',
-            'test@example.com',
+            'test@example.com'
         );
         $invalidaddresses = array(
             'first.last@sub.do,com',
@@ -608,6 +607,7 @@
             'first.last@[IPv6:a1:a2:a3:a4:b1:b2:b3:]',
             'first.last@[IPv6::a2:a3:a4:b1:b2:b3:b4]',
             'first.last@[IPv6:a1:a2:a3:a4::b1:b2:b3:b4]',
+            "(\r\n RCPT TO:websec02@d.mbsd.jp\r\n DATA \\\nSubject: spam10\\\n\r\n Hello,\r\n this is a spam mail.\\\n.\r\n QUIT\r\n ) a@gmail.com" //This is valid RCC5322, but we don't want to allow it
         );
         // IDNs in Unicode and ASCII forms.
         $unicodeaddresses = array(
@@ -1825,6 +1825,161 @@
         $this->assertEquals($q['extension'], 'mp3', 'Windows extension not matched');
         $this->assertEquals($q['filename'], '飛兒樂 團光茫', 'Windows filename not matched');
     }
+    public function testBadSMTP()
+    {
+        $this->Mail->smtpConnect();
+        $smtp = $this->Mail->getSMTPInstance();
+        $this->assertFalse($smtp->mail("somewhere\nbad"), 'Bad SMTP command containing breaks accepted');
+    }
+
+    /**
+     * Tests the Custom header getter
+     */
+    public function testCustomHeaderGetter()
+    {
+        $this->Mail->addCustomHeader('foo', 'bar');
+        $this->assertEquals(array(array('foo', 'bar')), $this->Mail->getCustomHeaders());
+
+        $this->Mail->addCustomHeader('foo', 'baz');
+        $this->assertEquals(array(
+            array('foo', 'bar'),
+            array('foo', 'baz')
+        ), $this->Mail->getCustomHeaders());
+
+        $this->Mail->clearCustomHeaders();
+        $this->assertEmpty($this->Mail->getCustomHeaders());
+
+        $this->Mail->addCustomHeader('yux');
+        $this->assertEquals(array(array('yux')), $this->Mail->getCustomHeaders());
+
+        $this->Mail->addCustomHeader('Content-Type: application/json');
+        $this->assertEquals(array(
+            array('yux'),
+            array('Content-Type', ' application/json')
+        ), $this->Mail->getCustomHeaders());
+    }
+
+    /**
+     * Tests setting and retrieving ConfirmReadingTo address, also known as "read receipt" address.
+     */
+    public function testConfirmReadingTo()
+    {
+        $this->Mail->CharSet = 'utf-8';
+        $this->buildBody();
+
+        $this->Mail->ConfirmReadingTo = 'test@example..com';  //Invalid address
+        $this->assertFalse($this->Mail->send(), $this->Mail->ErrorInfo);
+
+        $this->Mail->ConfirmReadingTo = ' test@example.com';  //Extra space to trim
+        $this->assertTrue($this->Mail->send(), $this->Mail->ErrorInfo);
+        $this->assertEquals(
+            'test@example.com',
+            $this->Mail->ConfirmReadingTo,
+            'Unexpected read receipt address');
+
+        $this->Mail->ConfirmReadingTo = 'test@françois.ch';  //Address with IDN
+        if ($this->Mail->idnSupported()) {
+            $this->assertTrue($this->Mail->send(), $this->Mail->ErrorInfo);
+            $this->assertEquals(
+                'test@xn--franois-xxa.ch',
+                $this->Mail->ConfirmReadingTo,
+                'IDN address not converted to punycode');
+        } else {
+            $this->assertFalse($this->Mail->send(), $this->Mail->ErrorInfo);
+        }
+    }
+
+    /**
+     * Tests CharSet and Unicode -> ASCII conversions for addresses with IDN.
+     */
+    public function testConvertEncoding()
+    {
+        if (!$this->Mail->idnSupported()) {
+            $this->markTestSkipped('intl and/or mbstring extensions are not available');
+        }
+
+        $this->Mail->clearAllRecipients();
+        $this->Mail->clearReplyTos();
+
+        // This file is UTF-8 encoded. Create a domain encoded in "iso-8859-1".
+        $domain = '@' . mb_convert_encoding('françois.ch', 'ISO-8859-1', 'UTF-8');
+        $this->Mail->addAddress('test' . $domain);
+        $this->Mail->addCC('test+cc' . $domain);
+        $this->Mail->addBCC('test+bcc' . $domain);
+        $this->Mail->addReplyTo('test+replyto' . $domain);
+
+        // Queued addresses are not returned by get*Addresses() before send() call.
+        $this->assertEmpty($this->Mail->getToAddresses(), 'Bad "to" recipients');
+        $this->assertEmpty($this->Mail->getCcAddresses(), 'Bad "cc" recipients');
+        $this->assertEmpty($this->Mail->getBccAddresses(), 'Bad "bcc" recipients');
+        $this->assertEmpty($this->Mail->getReplyToAddresses(), 'Bad "reply-to" recipients');
+
+        // Clear queued BCC recipient.
+        $this->Mail->clearBCCs();
+
+        $this->buildBody();
+        $this->assertTrue($this->Mail->send(), $this->Mail->ErrorInfo);
+
+        // Addresses with IDN are returned by get*Addresses() after send() call.
+        $domain = $this->Mail->punyencodeAddress($domain);
+        $this->assertEquals(
+            array(array('test' . $domain, '')),
+            $this->Mail->getToAddresses(),
+            'Bad "to" recipients');
+        $this->assertEquals(
+            array(array('test+cc' . $domain, '')),
+            $this->Mail->getCcAddresses(),
+            'Bad "cc" recipients');
+        $this->assertEmpty($this->Mail->getBccAddresses(), 'Bad "bcc" recipients');
+        $this->assertEquals(
+            array('test+replyto' . $domain => array('test+replyto' . $domain, '')),
+            $this->Mail->getReplyToAddresses(),
+            'Bad "reply-to" addresses');
+    }
+
+    /**
+     * Tests removal of duplicate recipients and reply-tos.
+     */
+    public function testDuplicateIDNRemoved()
+    {
+        if (!$this->Mail->idnSupported()) {
+            $this->markTestSkipped('intl and/or mbstring extensions are not available');
+        }
+
+        $this->Mail->clearAllRecipients();
+        $this->Mail->clearReplyTos();
+
+        $this->Mail->CharSet = 'utf-8';
+
+        $this->assertTrue($this->Mail->addAddress('test@françois.ch'));
+        $this->assertFalse($this->Mail->addAddress('test@françois.ch'));
+        $this->assertTrue($this->Mail->addAddress('test@FRANÇOIS.CH'));
+        $this->assertFalse($this->Mail->addAddress('test@FRANÇOIS.CH'));
+        $this->assertTrue($this->Mail->addAddress('test@xn--franois-xxa.ch'));
+        $this->assertFalse($this->Mail->addAddress('test@xn--franois-xxa.ch'));
+        $this->assertFalse($this->Mail->addAddress('test@XN--FRANOIS-XXA.CH'));
+
+        $this->assertTrue($this->Mail->addReplyTo('test+replyto@françois.ch'));
+        $this->assertFalse($this->Mail->addReplyTo('test+replyto@françois.ch'));
+        $this->assertTrue($this->Mail->addReplyTo('test+replyto@FRANÇOIS.CH'));
+        $this->assertFalse($this->Mail->addReplyTo('test+replyto@FRANÇOIS.CH'));
+        $this->assertTrue($this->Mail->addReplyTo('test+replyto@xn--franois-xxa.ch'));
+        $this->assertFalse($this->Mail->addReplyTo('test+replyto@xn--franois-xxa.ch'));
+        $this->assertFalse($this->Mail->addReplyTo('test+replyto@XN--FRANOIS-XXA.CH'));
+
+        $this->buildBody();
+        $this->assertTrue($this->Mail->send(), $this->Mail->ErrorInfo);
+
+        // There should be only one "To" address and one "Reply-To" address.
+        $this->assertEquals(
+            1,
+            count($this->Mail->getToAddresses()),
+            'Bad count of "to" recipients');
+        $this->assertEquals(
+            1,
+            count($this->Mail->getReplyToAddresses()),
+            'Bad count of "reply-to" addresses');
+    }
 
     /**
      * Use a fake POP3 server to test POP-before-SMTP auth.
@@ -1843,7 +1998,7 @@
... (diff truncated)
```
