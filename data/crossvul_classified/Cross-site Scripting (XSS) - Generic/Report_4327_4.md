# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4327_4
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4327_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-26 of the vulnerable file.

<?php namespace Tests\Uploads;

use BookStack\Uploads\Attachment;
use BookStack\Entities\Page;
use BookStack\Auth\Permissions\PermissionService;
use Tests\TestCase;

class AttachmentTest extends TestCase
{
    /**
     * Get a test file that can be uploaded
     * @param $fileName
     * @return \Illuminate\Http\UploadedFile
     */
    protected function getTestFile($fileName)
    {
        return new \Illuminate\Http\UploadedFile(base_path('tests/test-data/test-file.txt'), $fileName, 'text/plain', 55, null, true);
    }

    /**
     * Uploads a file with the given name.
     * @param $name
     * @param int $uploadedTo
     * @return \Illuminate\Foundation\Testing\TestResponse
     */
    protected function uploadFile($name, $uploadedTo = 0)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3,39 +3,51 @@
 use BookStack\Uploads\Attachment;
 use BookStack\Entities\Page;
 use BookStack\Auth\Permissions\PermissionService;
+use BookStack\Uploads\AttachmentService;
+use Illuminate\Http\UploadedFile;
 use Tests\TestCase;
+use Tests\TestResponse;
 
 class AttachmentTest extends TestCase
 {
     /**
      * Get a test file that can be uploaded
-     * @param $fileName
-     * @return \Illuminate\Http\UploadedFile
-     */
-    protected function getTestFile($fileName)
-    {
-        return new \Illuminate\Http\UploadedFile(base_path('tests/test-data/test-file.txt'), $fileName, 'text/plain', 55, null, true);
+     */
+    protected function getTestFile(string $fileName): UploadedFile
+    {
+        return new UploadedFile(base_path('tests/test-data/test-file.txt'), $fileName, 'text/plain', 55, null, true);
     }
 
     /**
      * Uploads a file with the given name.
-     * @param $name
-     * @param int $uploadedTo
-     * @return \Illuminate\Foundation\Testing\TestResponse
-     */
-    protected function uploadFile($name, $uploadedTo = 0)
+     */
+    protected function uploadFile(string $name, int $uploadedTo = 0): \Illuminate\Foundation\Testing\TestResponse
     {
         $file = $this->getTestFile($name);
         return $this->call('POST', '/attachments/upload', ['uploaded_to' => $uploadedTo], [], ['file' => $file], []);
     }
 
     /**
+     * Create a new attachment
+     */
+    protected function createAttachment(Page $page): Attachment
+    {
+        $this->post('attachments/link', [
+            'attachment_link_url' => 'https://example.com',
+            'attachment_link_name' => 'Example Attachment Link',
+            'attachment_link_uploaded_to' => $page->id,
+        ]);
+
+        return Attachment::query()->latest()->first();
+    }
+
+    /**
      * Delete all uploaded files.
      * To assist with cleanup.
      */
     protected function deleteUploads()
     {
-        $fileService = $this->app->make(\BookStack\Uploads\AttachmentService::class);
+        $fileService = $this->app->make(AttachmentService::class);
         foreach (Attachment::all() as $file) {
             $fileService->deleteFile($file);
         }
@@ -145,21 +157,14 @@
         $page = Page::first();
         $this->asAdmin();
 
-        $this->call('POST', 'attachments/link', [
-            'attachment_link_url' => 'https://example.com',
-            'attachment_link_name' => 'Example Attachment Link',
-            'attachment_link_uploaded_to' => $page->id,
-        ]);
-
-        $attachmentId = Attachment::first()->id;
-
-        $update = $this->call('PUT', 'attachments/' . $attachmentId, [
+        $attachment = $this->createAttachment($page);
+        $update = $this->call('PUT', 'attachments/' . $attachment->id, [
             'attachment_edit_name' => 'My new attachment name',
             'attachment_edit_url' => 'https://test.example.com'
         ]);
 
         $expectedData = [
-            'id' => $attachmentId,
+            'id' => $attachment->id,
             'path' => 'https://test.example.com',
             'name' => 'My new attachment name',
             'uploaded_to' => $page->id
@@ -242,4 +247,45 @@
 
         $this->deleteUploads();
     }
+
+    public function test_data_and_js_links_cannot_be_attached_to_a_page()
+    {
+        $page = Page::first();
+        $this->asAdmin();
+
+        $badLinks = [
+            'javascript:alert("bunny")',
+            ' javascript:alert("bunny")',
+            'JavaScript:alert("bunny")',
+            "\t\n\t\nJavaScript:alert(\"bunny\")",
+            "data:text/html;<a></a>",
+            "Data:text/html;<a></a>",
+            "Data:text/html;<a></a>",
+        ];
+
+        foreach ($badLinks as $badLink) {
+            $linkReq = $this->post('attachments/link', [
+                'attachment_link_url' => $badLink,
+                'attachment_link_name' => 'Example Attachment Link',
+                'attachment_link_uploaded_to' => $page->id,
+            ]);
+            $linkReq->assertStatus(422);
+            $this->assertDatabaseMissing('attachments', [
+                'path' => $badLink,
+            ]);
+        }
+
+        $attachment = $this->createAttachment($page);
+
+        foreach ($badLinks as $badLink) {
+            $linkReq = $this->put('attachments/' . $attachment->id, [
+                'attachment_edit_url' => $badLink,
+                'attachment_edit_name' => 'Example Attachment Link',
+            ]);
+            $linkReq->assertStatus(422);
+            $this->assertDatabaseMissing('attachments', [
+                'path' => $badLink,
+            ]);
+        }
+    }
 }
```
