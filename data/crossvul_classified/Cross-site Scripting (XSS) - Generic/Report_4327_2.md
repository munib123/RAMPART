# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4327_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4327_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 71-114 of the vulnerable file.

     */
    public function saveUpdatedUpload(UploadedFile $uploadedFile, Attachment $attachment)
    {
        if (!$attachment->external) {
            $this->deleteFileInStorage($attachment);
        }

        $attachmentName = $uploadedFile->getClientOriginalName();
        $attachmentPath = $this->putFileInStorage($uploadedFile);

        $attachment->name = $attachmentName;
        $attachment->path = $attachmentPath;
        $attachment->external = false;
        $attachment->extension = $uploadedFile->getClientOriginalExtension();
        $attachment->save();
        return $attachment;
    }

    /**
     * Save a new File attachment from a given link and name.
     * @param string $name
     * @param string $link
     * @param int $page_id
     * @return Attachment
     */
    public function saveNewFromLink($name, $link, $page_id)
    {
        $largestExistingOrder = Attachment::where('uploaded_to', '=', $page_id)->max('order');
        return Attachment::forceCreate([
            'name' => $name,
            'path' => $link,
            'external' => true,
            'extension' => '',
            'uploaded_to' => $page_id,
            'created_by' => user()->id,
            'updated_by' => user()->id,
            'order' => $largestExistingOrder + 1
        ]);
    }

    /**
     * Updates the ordering for a listing of attached files.
     */
    public function updateFileOrderWithinPage(array $attachmentOrder, string $pageId)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -88,12 +88,8 @@
 
     /**
      * Save a new File attachment from a given link and name.
-     * @param string $name
-     * @param string $link
-     * @param int $page_id
-     * @return Attachment
      */
-    public function saveNewFromLink($name, $link, $page_id)
+    public function saveNewFromLink(string $name, string $link, int $page_id): Attachment
     {
         $largestExistingOrder = Attachment::where('uploaded_to', '=', $page_id)->max('order');
         return Attachment::forceCreate([
@@ -123,13 +119,11 @@
 
     /**
      * Update the details of a file.
-     * @param Attachment $attachment
-     * @param $requestData
-     * @return Attachment
      */
-    public function updateFile(Attachment $attachment, $requestData)
+    public function updateFile(Attachment $attachment, array $requestData): Attachment
     {
         $attachment->name = $requestData['name'];
+
         if (isset($requestData['link']) && trim($requestData['link']) !== '') {
             $attachment->path = $requestData['link'];
             if (!$attachment->external) {
@@ -137,6 +131,7 @@
                 $attachment->external = true;
             }
         }
+
         $attachment->save();
         return $attachment;
     }
```
