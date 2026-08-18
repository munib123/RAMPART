# CrossVul Fix Pair: Improper Input Validation in php
**Pair ID:** 813_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `813_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```php
Lines 692-712 of the vulnerable file.


        $this->socket->expects($this->at(1))->method('read')->will($this->returnValue("220 Welcome message\r\n"));
        $this->socket->expects($this->at(2))->method('write')->with("EHLO localhost\r\n");
        $this->socket->expects($this->at(3))->method('read')->will($this->returnValue("250 OK\r\n"));

        $this->socket->expects($this->at(4))->method('write')->with("MAIL FROM:<noreply@cakephp.org>\r\n");
        $this->socket->expects($this->at(5))->method('read')->will($this->returnValue("250 OK\r\n"));
        $this->socket->expects($this->at(6))->method('write')->with("RCPT TO:<cake@cakephp.org>\r\n");
        $this->socket->expects($this->at(7))->method('read')->will($this->returnValue("250 OK\r\n"));

        $this->socket->expects($this->at(8))->method('write')->with("DATA\r\n");
        $this->socket->expects($this->at(9))->method('read')->will($this->returnValue("354 OK\r\n"));
        $this->socket->expects($this->at(10))->method('write')->with($this->stringContains('First Line'));
        $this->socket->expects($this->at(11))->method('read')->will($this->returnValue("250 OK\r\n"));

        $this->socket->expects($this->at(12))->method('write')->with("QUIT\r\n");
        $this->socket->expects($this->at(13))->method('disconnect');

        $this->SmtpTransport->send($email);
    }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -709,4 +709,25 @@
 
         $this->SmtpTransport->send($email);
     }
+
+    /**
+     * Ensure that unserialized transports have no connection.
+     *
+     * @return void
+     */
+    public function testSerializeCleanupSocket()
+    {
+        $this->socket->expects($this->at(0))->method('connect')->will($this->returnValue(true));
+        $this->socket->expects($this->at(1))->method('read')->will($this->returnValue("220 Welcome message\r\n"));
+        $this->socket->expects($this->at(2))->method('write')->with("EHLO localhost\r\n");
+        $this->socket->expects($this->at(3))->method('read')->will($this->returnValue("250 OK\r\n"));
+
+        $smtpTransport = new SmtpTestTransport();
+        $smtpTransport->setSocket($this->socket);
+        $smtpTransport->connect();
+
+        $result = unserialize(serialize($smtpTransport));
+        $this->assertAttributeEquals(null, '_socket', $result);
+        $this->assertFalse($result->connected());
+    }
 }
```
