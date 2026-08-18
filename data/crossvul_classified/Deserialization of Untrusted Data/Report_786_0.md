# CrossVul Fix Pair: Deserialization of Untrusted Data in php
**Pair ID:** 786_0
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `786_0`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```php
Lines 7-47 of the vulnerable file.

 * - Pimcore Enterprise License (PEL)
 * Full copyright and license information is available in
 * LICENSE.md which is distributed with this source code.
 *
 * @copyright  Copyright (c) Pimcore GmbH (http://www.pimcore.org)
 * @license    http://www.pimcore.org/license     GPLv3 and PEL
 */

namespace Pimcore\Bundle\AdminBundle\Controller\Admin\DataObject;

use Pimcore\Bundle\AdminBundle\Controller\AdminController;
use Pimcore\Bundle\AdminBundle\HttpFoundation\JsonResponse;
use Pimcore\Controller\EventedControllerInterface;
use Pimcore\Db;
use Pimcore\Event\AdminEvents;
use Pimcore\Logger;
use Pimcore\Model;
use Pimcore\Model\Asset;
use Pimcore\Model\DataObject;
use Pimcore\Model\Document;
use Symfony\Component\EventDispatcher\GenericEvent;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\FilterControllerEvent;
use Symfony\Component\HttpKernel\Event\FilterResponseEvent;
use Symfony\Component\Routing\Annotation\Route;

/**
 * @Route("/class")
 */
class ClassController extends AdminController implements EventedControllerInterface
{
    /**
     * @Route("/get-document-types", methods={"GET"})
     *
     * @param Request $request
     *
     * @return JsonResponse
     */
    public function getDocumentTypesAction(Request $request)
    {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -24,9 +24,11 @@
 use Pimcore\Model\Asset;
 use Pimcore\Model\DataObject;
 use Pimcore\Model\Document;
+use Pimcore\Tool\Session;
 use Symfony\Component\EventDispatcher\GenericEvent;
 use Symfony\Component\HttpFoundation\Request;
 use Symfony\Component\HttpFoundation\Response;
+use Symfony\Component\HttpFoundation\Session\Attribute\AttributeBagInterface;
 use Symfony\Component\HttpKernel\Event\FilterControllerEvent;
 use Symfony\Component\HttpKernel\Event\FilterResponseEvent;
 use Symfony\Component\Routing\Annotation\Route;
@@ -1347,8 +1349,12 @@
         $tmpName = $_FILES['Filedata']['tmp_name'];
         $json = file_get_contents($tmpName);
 
-        $tmpName = PIMCORE_SYSTEM_TEMP_DIRECTORY . '/bulk-import.tmp';
+        $tmpName = PIMCORE_SYSTEM_TEMP_DIRECTORY . '/bulk-import-' . uniqid() . '.tmp';
         file_put_contents($tmpName, $json);
+
+        Session::useSession(function (AttributeBagInterface $session) use ($tmpName) {
+            $session->set('class_bulk_import_file', $tmpName);
+        }, 'pimcore_objects');
 
         $json = json_decode($json, true);
 
@@ -1363,7 +1369,7 @@
                     $className = $groupItem['className'];
 
                     $layoutData = ['className' => $className, 'name' => $groupItem['name']];
-                    $name = serialize($layoutData);
+                    $name = json_encode($layoutData);
                     $displayName = $className . ' / ' . $groupItem['name'];
                     $icon = 'database_lightning';
                 } else {
@@ -1382,7 +1388,7 @@
             }
         }
 
-        $response = $this->adminJson(['success' => true, 'filename' => $tmpName, 'data' => $result]);
+        $response = $this->adminJson(['success' => true, 'data' => $result]);
         $response->headers->set('Content-Type', 'text/html');
 
         return $response;
@@ -1404,9 +1410,10 @@
      */
     public function bulkCommitAction(Request $request)
     {
-        $filename = $request->get('filename');
         $data = json_decode($request->get('data'), true);
 
+        $session = Session::get('pimcore_objects');
+        $filename = $session->get('class_bulk_import_file');
         $json = @file_get_contents($filename);
         $json = json_decode($json, true);
 
@@ -1451,7 +1458,7 @@
 
                 return $this->adminJson(['success' => $success !== false]);
             } elseif ($type == 'customlayout') {
-                $layoutData = unserialize($data['name']);
+                $layoutData = json_decode($data['name'], true);
                 $className = $layoutData['className'];
                 $layoutName = $layoutData['name'];
 
```
