# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 4500_3
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4500_3`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 8-48 of the vulnerable file.

use Bolt\Storage\Entity\Users;
use Bolt\Tests\Controller\ControllerUnitTest;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManager;
use Symfony\Component\Security\Csrf\TokenStorage\SessionTokenStorage;

/**
 * Class to test correct operation of src/Controller/Async/FileManager.
 *
 * @author Gawain Lynch <gawain.lynch@gmail.com>
 **/
class FilesystemManagerTest extends ControllerUnitTest
{
    const FILESYSTEM = 'files';

    const FILE_NAME = '__phpunit_test_file_delete_me';
    const FILE_NAME_NOT_ALLOWED = '__phpunit_test_file_delete_me.exe';
    const FILE_NAME_2 = '__phpunit_test_file_2_delete_me';
    const FOLDER_NAME = '__phpunit_test_folder_delete_me';
    const FOLDER_NAME_2 = '__phpunit_test_folder_2_delete_me';

    private $oldFiles = [];

    /** @var CsrfToken */
    private $token;

    protected function setUp()
    {
        $tokenManager = new CsrfTokenManager(null, new SessionTokenStorage(new Session(new MockArraySessionStorage())));
        $this->setService('csrf', $tokenManager);
        $this->token = $tokenManager->refreshToken('bolt');
    }

    /**
     * Store the list of files in the files folder so we can delete any added files after we're done testing.
     *
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -25,9 +25,10 @@
 {
     const FILESYSTEM = 'files';
 
-    const FILE_NAME = '__phpunit_test_file_delete_me';
+    const FILE_NAME = '__phpunit_test_file_delete_me.txt';
     const FILE_NAME_NOT_ALLOWED = '__phpunit_test_file_delete_me.exe';
-    const FILE_NAME_2 = '__phpunit_test_file_2_delete_me';
+    const FILE_NAME_NOT_ALLOWED_2 = '__phpunit_test_file_delete_me';
+    const FILE_NAME_2 = '__phpunit_test_file_2_delete_me.txt';
     const FOLDER_NAME = '__phpunit_test_folder_delete_me';
     const FOLDER_NAME_2 = '__phpunit_test_folder_2_delete_me';
 
@@ -153,6 +154,23 @@
         $this->assertFalse($this->getService('filesystem')->has(self::FILESYSTEM . '://' . self::FILE_NAME_NOT_ALLOWED));
     }
 
+    public function testCreateFileInvalidExtension2()
+    {
+        $this->setRequest(Request::create('/async/file/create', 'POST', [
+            'namespace'  => self::FILESYSTEM,
+            'parentPath' => '',
+            'filename'   => self::FILE_NAME_NOT_ALLOWED_2,
+            'token'      => $this->token,
+        ]));
+        $response = $this->controller()->createFile($this->getRequest());
+
+        $this->assertInstanceOf(JsonResponse::class, $response);
+        $this->assertEquals(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
+
+        // Test whether the new file is not saved
+        $this->assertFalse($this->getService('filesystem')->has(self::FILESYSTEM . '://' . self::FILE_NAME_NOT_ALLOWED));
+    }
+
     /**
      * Duplicating a file five times should create FILENAME_copy1-5.EXT. This should work for both regular filenames
      * and dotfiles.
@@ -255,7 +273,7 @@
              * Object doesn't exist
              */
             $this->createObject($object, $data['old']);
-            $response = $this->renameObject($object, $data['old'] . '_nonexistent', $data['new']);
+            $response = $this->renameObject($object, $data['old'] . '_nonexistent.txt', $data['new']);
 
             $this->assertInstanceOf(JsonResponse::class, $response);
             $this->assertEquals(Response::HTTP_NOT_FOUND, $response->getStatusCode());
```
