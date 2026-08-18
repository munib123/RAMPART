# CrossVul Fix Pair: Improper Neutralization of Special Elements used in a Command ('Command Injection') in php
**Pair ID:** 4468_2
**Vulnerability Class:** Command Injection - Generic
**CWE:** CWE-77
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4468_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in a Command ('Command Injection') - Command injection vulnerabilities typically occur when: 1.

## Vulnerable Code
```php
Lines 227-267 of the vulnerable file.

        return $result;
    }

    /**
     * testCheckLoginPassEntity
     *
     * @return	void
     */
    public function testCheckLoginPassEntity()
    {
        $login=checkLoginPassEntity('loginbidon', 'passwordbidon', 1, array('dolibarr'));
        print __METHOD__." login=".$login."\n";
        $this->assertEquals($login, '');

        $login=checkLoginPassEntity('admin', 'passwordbidon', 1, array('dolibarr'));
        print __METHOD__." login=".$login."\n";
        $this->assertEquals($login, '');

        $login=checkLoginPassEntity('admin', 'admin', 1, array('dolibarr'));            // Should works because admin/admin exists
        print __METHOD__." login=".$login."\n";
        $this->assertEquals($login, 'admin');

        $login=checkLoginPassEntity('admin', 'admin', 1, array('http','dolibarr'));    // Should work because of second authetntication method
        print __METHOD__." login=".$login."\n";
        $this->assertEquals($login, 'admin');

        $login=checkLoginPassEntity('admin', 'admin', 1, array('forceuser'));
        print __METHOD__." login=".$login."\n";
        $this->assertEquals($login, '');    // Expected '' because should failed because login 'auto' does not exists
    }

    /**
     * testEncodeDecode
     *
     * @return number
     */
    public function testEncodeDecode()
    {
        $stringtotest="This is a string to test encode/decode. This is a string to test encode/decode. This is a string to test encode/decode.";

        $encodedstring=dol_encode($stringtotest);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -244,7 +244,7 @@
 
         $login=checkLoginPassEntity('admin', 'admin', 1, array('dolibarr'));            // Should works because admin/admin exists
         print __METHOD__." login=".$login."\n";
-        $this->assertEquals($login, 'admin');
+        $this->assertEquals($login, 'admin', 'The test to check if pass of user "admin" is "admin" has failed');
 
         $login=checkLoginPassEntity('admin', 'admin', 1, array('http','dolibarr'));    // Should work because of second authetntication method
         print __METHOD__." login=".$login."\n";
@@ -326,4 +326,27 @@
 		$result=restrictedArea($user, 'societe');
 		$this->assertEquals(1, $result);
     }
+
+    /**
+     * testDolSanitizeFileName
+     *
+     * @return void
+     */
+    public function testDolSanitizeFileName()
+    {
+    	global $conf,$user,$langs,$db;
+    	$conf=$this->savconf;
+    	$user=$this->savuser;
+    	$langs=$this->savlangs;
+    	$db=$this->savdb;
+
+    	//$dummyuser=new User($db);
+    	//$result=restrictedArea($dummyuser,'societe');
+
+    	$result=dol_sanitizeFileName('bad file | evilaction');
+    	$this->assertEquals('bad file _ evilaction', $result);
+
+    	$result=dol_sanitizeFileName('bad file --evilparam');
+    	$this->assertEquals('bad file _evilparam', $result);
+    }
 }
```
