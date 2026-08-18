# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 5085_7
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5085_7`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 356-396 of the vulnerable file.

            '<script src="https://www.google.com/recaptcha/api.js?hl=en"'
            . ' async defer></script>',
            $result
        );

        $this->assertContains(
            '<div class="g-recaptcha" data-sitekey="testpubkey">',
            $result
        );

        $attrInstance->setValue($restoreInstance);
    }

    /**
     * Test for PMA\libraries\plugins\auth\AuthenticationConfig::auth with headers
     *
     * @return void
     */
    public function testAuthHeader()
    {
        $restoreInstance = PMA\libraries\Response::getInstance();

        $mockResponse = $this->getMockBuilder('PMA\libraries\Response')
            ->disableOriginalConstructor()
            ->setMethods(array('isAjax', 'headersSent', 'header'))
            ->getMock();

        $mockResponse->expects($this->once())
            ->method('isAjax')
            ->with()
            ->will($this->returnValue(false));

        $mockResponse->expects($this->any())
            ->method('headersSent')
            ->with()
            ->will($this->returnValue(false));

        $mockResponse->expects($this->once())
            ->method('header')
            ->with('Location: http://www.phpmyadmin.net/logout' . ((SID) ? '?' . SID : ''));

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -373,17 +373,15 @@
      */
     public function testAuthHeader()
     {
+        $GLOBALS['cfg']['LoginCookieDeleteAll'] = false;
+        $GLOBALS['cfg']['Servers'] = array(1);
+
         $restoreInstance = PMA\libraries\Response::getInstance();
 
         $mockResponse = $this->getMockBuilder('PMA\libraries\Response')
             ->disableOriginalConstructor()
             ->setMethods(array('isAjax', 'headersSent', 'header'))
             ->getMock();
-
-        $mockResponse->expects($this->once())
-            ->method('isAjax')
-            ->with()
-            ->will($this->returnValue(false));
 
         $mockResponse->expects($this->any())
             ->method('headersSent')
@@ -398,12 +396,9 @@
         $attrInstance->setAccessible(true);
         $attrInstance->setValue($mockResponse);
 
-        $_REQUEST['old_usr'] = 'user1';
         $GLOBALS['cfg']['Server']['LogoutURL'] = 'http://www.phpmyadmin.net/logout';
 
-        $this->assertTrue(
-            $this->object->auth()
-        );
+        $this->object->logOut();
 
         $attrInstance->setValue($restoreInstance);
     }
@@ -454,20 +449,40 @@
      */
     public function testLogoutDelete()
     {
+        $restoreInstance = PMA\libraries\Response::getInstance();
+
+        $mockResponse = $this->getMockBuilder('PMA\libraries\Response')
+            ->disableOriginalConstructor()
+            ->setMethods(array('isAjax', 'headersSent', 'header'))
+            ->getMock();
+
+        $mockResponse->expects($this->any())
+            ->method('headersSent')
+            ->with()
+            ->will($this->returnValue(false));
+
+        $mockResponse->expects($this->once())
+            ->method('header')
+            ->with('Location: ./index.php' . ((SID) ? '?' . SID : ''));
+
+        $attrInstance = new ReflectionProperty('PMA\libraries\Response', '_instance');
+        $attrInstance->setAccessible(true);
+        $attrInstance->setValue($mockResponse);
+
         $GLOBALS['cfg']['Server']['auth_swekey_config'] = '';
         $GLOBALS['cfg']['CaptchaLoginPrivateKey'] = '';
         $GLOBALS['cfg']['CaptchaLoginPublicKey'] = '';
-        $_REQUEST['old_usr'] = 'pmaolduser';
         $GLOBALS['cfg']['LoginCookieDeleteAll'] = true;
         $GLOBALS['cfg']['Servers'] = array(1);
 
         $_COOKIE['pmaPass-0'] = 'test';
 
-        $this->object->authCheck();
+        $this->object->logOut();
 
         $this->assertFalse(
             isset($_COOKIE['pmaPass-0'])
         );
+        $attrInstance->setValue($restoreInstance);
     }
 
     /**
@@ -477,21 +492,40 @@
      */
     public function testLogout()
     {
+        $restoreInstance = PMA\libraries\Response::getInstance();
+
+        $mockResponse = $this->getMockBuilder('PMA\libraries\Response')
+            ->disableOriginalConstructor()
+            ->setMethods(array('isAjax', 'headersSent', 'header'))
+            ->getMock();
+
+        $mockResponse->expects($this->any())
+            ->method('headersSent')
+            ->with()
+            ->will($this->returnValue(false));
+
+        $mockResponse->expects($this->once())
+            ->method('header')
+            ->with('Location: ./index.php' . ((SID) ? '?' . SID : ''));
+
+        $attrInstance = new ReflectionProperty('PMA\libraries\Response', '_instance');
+        $attrInstance->setAccessible(true);
+        $attrInstance->setValue($mockResponse);
         $GLOBALS['cfg']['Server']['auth_swekey_config'] = '';
         $GLOBALS['cfg']['CaptchaLoginPrivateKey'] = '';
         $GLOBALS['cfg']['CaptchaLoginPublicKey'] = '';
-        $_REQUEST['old_usr'] = 'pmaolduser';
         $GLOBALS['cfg']['LoginCookieDeleteAll'] = false;
         $GLOBALS['cfg']['Servers'] = array(1);
         $GLOBALS['server'] = 1;
 
         $_COOKIE['pmaPass-1'] = 'test';
 
-        $this->object->authCheck();
+        $this->object->logOut();
 
         $this->assertFalse(
             isset($_COOKIE['pmaPass-1'])
         );
+        $attrInstance->setValue($restoreInstance);
     }
 
     /**
```
