# CrossVul Fix Pair: Improper Authentication in php
**Pair ID:** 4518_1
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4518_1`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```php
Lines 7-47 of the vulnerable file.

 * This source file is subject to the Open Software License (OSL 3.0)
 * that is bundled with this package in the file LICENSE.txt.
 * It is also available through the world-wide-web at this URL:
 * https://opensource.org/licenses/OSL-3.0
 * If you did not receive a copy of the license and are unable to
 * obtain it through the world-wide-web, please send an email
 * to license@prestashop.com so we can send you a copy immediately.
 *
 * DISCLAIMER
 *
 * Do not edit or add to this file if you wish to upgrade PrestaShop to newer
 * versions in the future. If you wish to customize PrestaShop for your
 * needs please refer to https://www.prestashop.com for more information.
 *
 * @author    PrestaShop SA <contact@prestashop.com>
 * @copyright 2007-2019 PrestaShop SA and Contributors
 * @license   https://opensource.org/licenses/OSL-3.0 Open Software License (OSL 3.0)
 * International Registered Trademark & Property of PrestaShop SA
 */
use Defuse\Crypto\Key;

class CookieCore
{
    /** @var array Contain cookie content in a key => value format */
    protected $_content = array();

    /** @var array Crypted cookie name for setcookie() */
    protected $_name;

    /** @var array expiration date for setcookie() */
    protected $_expire;

    /** @var array Website domain for setcookie() */
    protected $_domain;

    /** @var array Path for setcookie() */
    protected $_path;

    /** @var array cipher tool instance */
    protected $cipherTool;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -24,6 +24,8 @@
  * International Registered Trademark & Property of PrestaShop SA
  */
 use Defuse\Crypto\Key;
+use PrestaShop\PrestaShop\Core\Exception\CoreException;
+use PrestaShop\PrestaShop\Core\Session\SessionInterface;
 
 class CookieCore
 {
@@ -246,7 +248,8 @@
      */
     public function logout()
     {
-        $this->_content = array();
+        $this->deleteSession();
+        $this->_content = [];
         $this->encryptAndSetCookie();
         unset($_COOKIE[$this->_name]);
         $this->_modified = true;
@@ -453,4 +456,91 @@
     {
         return isset($_COOKIE[$this->_name]);
     }
+
+    /**
+     * Register a new session
+     *
+     * @param SessionInterface $session
+     */
+    public function registerSession(SessionInterface $session)
+    {
+        if (isset($this->id_employee)) {
+            $session->setUserId((int) $this->id_employee);
+        } elseif (isset($this->id_customer)) {
+            $session->setUserId((int) $this->id_customer);
+        } else {
+            throw new CoreException('Invalid user id');
+        }
+
+        $session->setToken(sha1(time() . uniqid()));
+        $session->add();
+
+        $this->session_id = $session->getId();
+        $this->session_token = $session->getToken();
+    }
+
+    /**
+     * Delete session
+     *
+     * @return bool
+     */
+    public function deleteSession()
+    {
+        if (!isset($this->session_id)) {
+            return false;
+        }
+
+        $session = $this->getSession($this->session_id);
+        if ($session !== null) {
+            $session->delete();
+
+            return true;
+        }
+
+        return false;
+    }
+
+    /**
+     * Check if this session is still alive
+     *
+     * @return bool
+     */
+    public function isSessionAlive()
+    {
+        if (!isset($this->session_id, $this->session_token)) {
+            return false;
+        }
+
+        $session = $this->getSession($this->session_id);
+
+        return
+            $session !== null
+            && $session->getToken() === $this->session_token
+            && (
+                (int) $this->id_employee === $session->getUserId()
+                || (int) $this->id_customer === $session->getUserId()
+            )
+        ;
+    }
+
+    /**
+     * Retrieve session based on a session id and the employee or
+     * customer id
+     *
+     * @return SessionInterface|null
+     */
+    public function getSession($sessionId)
+    {
+        if (isset($this->id_employee)) {
+            $session = new EmployeeSession($sessionId);
+        } elseif (isset($this->id_customer)) {
+            $session = new CustomerSession($sessionId);
+        }
+
+        if (!empty($session->getId())) {
+            return $session;
+        }
+
+        return null;
+    }
 }
```
