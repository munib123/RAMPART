# CrossVul Fix Pair: Authorization Bypass Through User-Controlled Key in php
**Pair ID:** 2846_1
**Vulnerability Class:** Insecure Direct Object Reference (IDOR)
**CWE:** CWE-639
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2846_1`)

## Vulnerability Information & PoC

## Description
Authorization Bypass Through User-Controlled Key - Retrieval of a user record occurs in the system based on some key value that is under user control.

## Vulnerable Code
```php
Lines 1-59 of the vulnerable file.

<?php

namespace Kanboard\Controller;

use Kanboard\Core\Controller\AccessForbiddenException;
use Kanboard\Core\Controller\PageNotFoundException;

/**
 * Comment Controller
 *
 * @package  Kanboard\Controller
 * @author   Frederic Guillot
 */
class CommentController extends BaseController
{
    /**
     * Get the current comment
     *
     * @access protected
     * @return array
     * @throws PageNotFoundException
     * @throws AccessForbiddenException
     */
    protected function getComment()
    {
        $comment = $this->commentModel->getById($this->request->getIntegerParam('comment_id'));

        if (empty($comment)) {
            throw new PageNotFoundException();
        }

        if (! $this->userSession->isAdmin() && $comment['user_id'] != $this->userSession->getId()) {
            throw new AccessForbiddenException();
        }

        return $comment;
    }

    /**
     * Add comment form
     *
     * @access public
     * @param array $values
     * @param array $errors
     * @throws AccessForbiddenException
     * @throws PageNotFoundException
     */
    public function create(array $values = array(), array $errors = array())
    {
        $project = $this->getProject();
        $task = $this->getTask();

        if (empty($values)) {
            $values = array(
                'user_id' => $this->userSession->getId(),
                'task_id' => $task['id'],
            );
        }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -14,29 +14,6 @@
 class CommentController extends BaseController
 {
     /**
-     * Get the current comment
-     *
-     * @access protected
-     * @return array
-     * @throws PageNotFoundException
-     * @throws AccessForbiddenException
-     */
-    protected function getComment()
-    {
-        $comment = $this->commentModel->getById($this->request->getIntegerParam('comment_id'));
-
-        if (empty($comment)) {
-            throw new PageNotFoundException();
-        }
-
-        if (! $this->userSession->isAdmin() && $comment['user_id'] != $this->userSession->getId()) {
-            throw new AccessForbiddenException();
-        }
-
-        return $comment;
-    }
-
-    /**
      * Add comment form
      *
      * @access public
@@ -49,14 +26,6 @@
     {
         $project = $this->getProject();
         $task = $this->getTask();
-
-        if (empty($values)) {
-            $values = array(
-                'user_id' => $this->userSession->getId(),
-                'task_id' => $task['id'],
-            );
-        }
-
         $values['project_id'] = $task['project_id'];
 
         $this->response->html($this->helper->layout->task('comment/create', array(
@@ -106,7 +75,7 @@
     public function edit(array $values = array(), array $errors = array())
     {
         $task = $this->getTask();
-        $comment = $this->getComment();
+        $comment = $this->getComment($task);
 
         if (empty($values)) {
             $values = $comment;
@@ -130,9 +99,13 @@
     public function update()
     {
         $task = $this->getTask();
-        $this->getComment();
+        $comment = $this->getComment($task);
 
         $values = $this->request->getValues();
+        $values['id'] = $comment['id'];
+        $values['task_id'] = $task['id'];
+        $values['user_id'] = $comment['user_id'];
+
         list($valid, $errors) = $this->commentValidator->validateModification($values);
 
         if ($valid) {
@@ -157,7 +130,7 @@
     public function confirm()
     {
         $task = $this->getTask();
-        $comment = $this->getComment();
+        $comment = $this->getComment($task);
 
         $this->response->html($this->template->render('comment/remove', array(
             'comment' => $comment,
@@ -175,7 +148,7 @@
     {
         $this->checkCSRFParam();
         $task = $this->getTask();
-        $comment = $this->getComment();
+        $comment = $this->getComment($task);
 
         if ($this->commentModel->remove($comment['id'])) {
             $this->flash->success(t('Comment removed successfully.'));
```
