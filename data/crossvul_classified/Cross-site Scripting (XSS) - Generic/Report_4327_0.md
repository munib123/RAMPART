# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4327_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4327_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 93-133 of the vulnerable file.

        $attachment = $this->attachment->findOrFail($attachmentId);

        $this->checkOwnablePermission('page-update', $attachment->page);
        $this->checkOwnablePermission('attachment-create', $attachment);

        return view('attachments.manager-edit-form', [
            'attachment' => $attachment,
        ]);
    }

    /**
     * Update the details of an existing file.
     */
    public function update(Request $request, string $attachmentId)
    {
        $attachment = $this->attachment->newQuery()->findOrFail($attachmentId);

        try {
            $this->validate($request, [
                'attachment_edit_name' => 'required|string|min:1|max:255',
                'attachment_edit_url' =>  'string|min:1|max:255'
            ]);
        } catch (ValidationException $exception) {
            return response()->view('attachments.manager-edit-form', array_merge($request->only(['attachment_edit_name', 'attachment_edit_url']), [
                'attachment' => $attachment,
                'errors' => new MessageBag($exception->errors()),
            ]), 422);
        }

        $this->checkOwnablePermission('view', $attachment->page);
        $this->checkOwnablePermission('page-update', $attachment->page);
        $this->checkOwnablePermission('attachment-create', $attachment);

        $attachment = $this->attachmentService->updateFile($attachment, [
            'name' => $request->get('attachment_edit_name'),
            'link' => $request->get('attachment_edit_url'),
        ]);

        return view('attachments.manager-edit-form', [
            'attachment' => $attachment,
        ]);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -110,7 +110,7 @@
         try {
             $this->validate($request, [
                 'attachment_edit_name' => 'required|string|min:1|max:255',
-                'attachment_edit_url' =>  'string|min:1|max:255'
+                'attachment_edit_url' =>  'string|min:1|max:255|safe_url'
             ]);
         } catch (ValidationException $exception) {
             return response()->view('attachments.manager-edit-form', array_merge($request->only(['attachment_edit_name', 'attachment_edit_url']), [
@@ -145,7 +145,7 @@
             $this->validate($request, [
                 'attachment_link_uploaded_to' => 'required|integer|exists:pages,id',
                 'attachment_link_name' => 'required|string|min:1|max:255',
-                'attachment_link_url' =>  'required|string|min:1|max:255'
+                'attachment_link_url' =>  'required|string|min:1|max:255|safe_url'
             ]);
         } catch (ValidationException $exception) {
             return response()->view('attachments.manager-link-form', array_merge($request->only(['attachment_link_name', 'attachment_link_url']), [
@@ -161,7 +161,7 @@
 
         $attachmentName = $request->get('attachment_link_name');
         $link = $request->get('attachment_link_url');
-        $attachment = $this->attachmentService->saveNewFromLink($attachmentName, $link, $pageId);
+        $attachment = $this->attachmentService->saveNewFromLink($attachmentName, $link, intval($pageId));
 
         return view('attachments.manager-link-form', [
             'pageId' => $pageId,
```
