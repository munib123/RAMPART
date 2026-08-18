# CrossVul Fix Pair: Authorization Bypass Through User-Controlled Key in php
**Pair ID:** 2846_0
**Vulnerability Class:** Insecure Direct Object Reference (IDOR)
**CWE:** CWE-639
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2846_0`)

## Vulnerability Information & PoC

## Description
Authorization Bypass Through User-Controlled Key - Retrieval of a user record occurs in the system based on some key value that is under user control.

## Vulnerable Code
```php
Lines 121-168 of the vulnerable file.

     * @access protected
     * @return array
     * @throws PageNotFoundException
     * @throws AccessForbiddenException
     */
    protected function getUser()
    {
        $user = $this->userModel->getById($this->request->getIntegerParam('user_id', $this->userSession->getId()));

        if (empty($user)) {
            throw new PageNotFoundException();
        }

        if (! $this->userSession->isAdmin() && $this->userSession->getId() != $user['id']) {
            throw new AccessForbiddenException();
        }

        return $user;
    }

    /**
     * Get the current subtask
     *
     * @access protected
     * @return array
     * @throws PageNotFoundException
     */
    protected function getSubtask()
    {
        $subtask = $this->subtaskModel->getById($this->request->getIntegerParam('subtask_id'));

        if (empty($subtask)) {
            throw new PageNotFoundException();
        }

        return $subtask;
    }

    protected function getColumn(array $project)
    {
        $column = $this->columnModel->getById($this->request->getIntegerParam('column_id'));

        if (empty($column)) {
            throw new PageNotFoundException();
        }

        if ($column['project_id'] != $project['id']) {
            throw new AccessForbiddenException();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -138,14 +138,7 @@
         return $user;
     }
 
-    /**
-     * Get the current subtask
-     *
-     * @access protected
-     * @return array
-     * @throws PageNotFoundException
-     */
-    protected function getSubtask()
+    protected function getSubtask(array $task)
     {
         $subtask = $this->subtaskModel->getById($this->request->getIntegerParam('subtask_id'));
 
@@ -153,9 +146,62 @@
             throw new PageNotFoundException();
         }
 
+        if ($subtask['task_id'] != $task['id']) {
+            throw new AccessForbiddenException();
+        }
+
         return $subtask;
     }
 
+    protected function getComment(array $task)
+    {
+        $comment = $this->commentModel->getById($this->request->getIntegerParam('comment_id'));
+
+        if (empty($comment)) {
+            throw new PageNotFoundException();
+        }
+
+        if (! $this->userSession->isAdmin() && $comment['user_id'] != $this->userSession->getId()) {
+            throw new AccessForbiddenException();
+        }
+
+        if ($comment['task_id'] != $task['id']) {
+            throw new AccessForbiddenException();
+        }
+
+        return $comment;
+    }
+
+    protected function getExternalTaskLink(array $task)
+    {
+        $link = $this->taskExternalLinkModel->getById($this->request->getIntegerParam('link_id'));
+
+        if (empty($link)) {
+            throw new PageNotFoundException();
+        }
+
+        if ($link['task_id'] != $task['id']) {
+            throw new AccessForbiddenException();
+        }
+
+        return $link;
+    }
+
+    protected function getInternalTaskLink(array $task)
+    {
+        $link = $this->taskLinkModel->getById($this->request->getIntegerParam('link_id'));
+
+        if (empty($link)) {
+            throw new PageNotFoundException();
+        }
+
+        if ($link['task_id'] != $task['id']) {
+            throw new AccessForbiddenException();
+        }
+
+        return $link;
+    }
+
     protected function getColumn(array $project)
     {
         $column = $this->columnModel->getById($this->request->getIntegerParam('column_id'));
```
