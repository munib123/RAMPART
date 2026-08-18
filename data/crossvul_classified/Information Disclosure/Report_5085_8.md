# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 5085_8
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5085_8`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 106-148 of the vulnerable file.

            ->method('headersSent')
            ->with()
            ->will($this->returnValue(false));

        $mockResponse->expects($this->exactly($set_title * 6))
            ->method('addHTML')
            ->with();

        $attrInstance = new ReflectionProperty('PMA\libraries\Response', '_instance');
        $attrInstance->setAccessible(true);
        $attrInstance->setValue($mockResponse);

        $headers = array_slice(func_get_args(), 3);

        $header_method = $mockResponse->expects($this->exactly(count($headers)))
            ->method('header');

        call_user_func_array(array($header_method, 'withConsecutive'), $headers);

        try {
            $this->assertFalse(
                $this->object->auth()
            );
        } finally {
            $attrInstance->setValue($restoreInstance);
        }
    }

    /**
     * Test for PMA\libraries\plugins\auth\AuthenticationHttp::auth
     *
     * @return void
     */
    public function testAuthLogoutUrl()
    {

        $_REQUEST['old_usr'] = '1';
        $GLOBALS['cfg']['Server']['LogoutURL'] = 'http://phpmyadmin.net/logout';

        $this->doMockResponse(
            0, 0, 0,
            array('Location: http://phpmyadmin.net/logout' . ((SID) ? '?' . SID : ''))
        );
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -123,9 +123,13 @@
         call_user_func_array(array($header_method, 'withConsecutive'), $headers);
 
         try {
-            $this->assertFalse(
-                $this->object->auth()
-            );
+            if (!empty($_REQUEST['old_usr'])) {
+                $this->object->logOut();
+            } else {
+                $this->assertFalse(
+                    $this->object->auth()
+                );
+            }
         } finally {
             $attrInstance->setValue($restoreInstance);
         }
```
