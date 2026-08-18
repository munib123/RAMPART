# CrossVul Fix Pair: Improper Restriction of Excessive Authentication Attempts in php
**Pair ID:** 1229_0
**Vulnerability Class:** Improper Restriction of Authentication Attempts
**CWE:** CWE-307
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1229_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Excessive Authentication Attempts - The product does not implement sufficient measures to prevent multiple failed authentication attempts within a short time frame, making it more susceptible to brute force attacks.

## Vulnerable Code
```php
Lines 5-45 of the vulnerable file.

 * This source file is available under two different licenses:
 * - GNU General Public License version 3 (GPLv3)
 * - Pimcore Enterprise License (PEL)
 * Full copyright and license information is available in
 * LICENSE.md which is distributed with this source code.
 *
 * @copyright  Copyright (c) Pimcore GmbH (http://www.pimcore.org)
 * @license    http://www.pimcore.org/license     GPLv3 and PEL
 */

namespace Pimcore\Bundle\AdminBundle\Controller\Admin;

use Pimcore\Bundle\AdminBundle\Controller\AdminController;
use Pimcore\Bundle\AdminBundle\Controller\BruteforceProtectedControllerInterface;
use Pimcore\Bundle\AdminBundle\Security\BruteforceProtectionHandler;
use Pimcore\Config;
use Pimcore\Controller\Configuration\TemplatePhp;
use Pimcore\Controller\EventedControllerInterface;
use Pimcore\Event\Admin\Login\LostPasswordEvent;
use Pimcore\Event\AdminEvents;
use Pimcore\Model\User;
use Pimcore\Templating\Model\ViewModel;
use Pimcore\Tool;
use Pimcore\Tool\Authentication;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\FilterControllerEvent;
use Symfony\Component\HttpKernel\Event\FilterResponseEvent;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\Security\Core\User\UserInterface;

class LoginController extends AdminController implements BruteforceProtectedControllerInterface, EventedControllerInterface
{
    public function onKernelController(FilterControllerEvent $event)
    {
        // use browser language for login page if possible
        $locale = 'en';
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -22,6 +22,7 @@
 use Pimcore\Controller\EventedControllerInterface;
 use Pimcore\Event\Admin\Login\LostPasswordEvent;
 use Pimcore\Event\AdminEvents;
+use Pimcore\Logger;
 use Pimcore\Model\User;
 use Pimcore\Templating\Model\ViewModel;
 use Pimcore\Tool;
@@ -116,29 +117,28 @@
     public function lostpasswordAction(Request $request, BruteforceProtectionHandler $bruteforceProtectionHandler)
     {
         $view = $this->buildLoginPageViewModel();
-        $view->success = false;
-
-        // TODO is the error on the view used somewhere?
+        $error = null;
+
         if ($request->getMethod() === 'POST' && $username = $request->get('username')) {
             $user = User::getByName($username);
 
             if ($user instanceof User) {
                 if (!$user->isActive()) {
-                    $view->error = 'user inactive';
+                    $error = 'user inactive';
                 }
 
                 if (!$user->getEmail()) {
-                    $view->error = 'user has no email address';
+                    $error = 'user has no email address';
                 }
 
                 if (!$user->getPassword()) {
-                    $view->error = 'user has no password';
+                    $error = 'user has no password';
                 }
             } else {
-                $view->error = 'user unknown';
-            }
-
-            if (!$view->error) {
+                $error = 'user unknown';
+            }
+
+            if (!$error) {
                 $token = Authentication::generateToken($username, $user->getPassword());
 
                 $loginUrl = $this->generateUrl('pimcore_admin_login_check', [
@@ -163,14 +163,13 @@
                     if ($event->hasResponse()) {
                         return $event->getResponse();
                     }
-
-                    $view->success = true;
                 } catch (\Exception $e) {
-                    $view->error = 'could not send email';
-                }
-            }
-
-            if ($view->error) {
+                    $error = 'could not send email';
+                }
+            }
+
+            if ($error) {
+                Logger::error('Lost password service: ' . $error);
                 $bruteforceProtectionHandler->addEntry($request->get('username'), $request);
             }
         }
```
