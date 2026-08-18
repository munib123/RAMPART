# CrossVul Fix Pair: Inappropriate Encoding for Output Context in php
**Pair ID:** 1226_0
**Vulnerability Class:** Inappropriate Encoding for Output Context
**CWE:** CWE-838
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1226_0`)

## Vulnerability Information & PoC

## Description
Inappropriate Encoding for Output Context - This weakness can cause the downstream component to use a decoding method that produces different data than what the product intended to send.

## Vulnerable Code
```php
Lines 3-43 of the vulnerable file.

 * Pimcore
 *
 * This source file is available under two different licenses:
 * - GNU General Public License version 3 (GPLv3)
 * - Pimcore Enterprise License (PEL)
 * Full copyright and license information is available in
 * LICENSE.md which is distributed with this source code.
 *
 * @copyright  Copyright (c) Pimcore GmbH (http://www.pimcore.org)
 * @license    http://www.pimcore.org/license     GPLv3 and PEL
 */

declare(strict_types=1);

namespace Pimcore\Model\Notification\Service;

use Pimcore\Model\Element\ElementInterface;
use Pimcore\Model\Notification;
use Pimcore\Model\Notification\Listing;
use Pimcore\Model\User;

class NotificationService
{
    /** @var UserService */
    private $userService;

    /**
     * NotificationService constructor.
     *
     * @param UserService $userService
     */
    public function __construct(UserService $userService)
    {
        $this->userService = $userService;
    }

    /**
     * @param int $userId
     * @param int $fromUser
     * @param string $title
     * @param string $message
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -20,6 +20,7 @@
 use Pimcore\Model\Notification;
 use Pimcore\Model\Notification\Listing;
 use Pimcore\Model\User;
+use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
 
 class NotificationService
 {
@@ -145,6 +146,10 @@
     {
         $this->beginTransaction();
         $notification = $this->find($id);
+
+        if($notification->getRecipient()->getId() != $recipientId) {
+            throw new AccessDeniedHttpException();
+        }
 
         if ($recipientId && $recipientId == $notification->getRecipient()->getId()) {
             $notification->setRead(true);
```
