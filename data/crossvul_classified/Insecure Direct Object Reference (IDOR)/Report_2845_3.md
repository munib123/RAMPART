# CrossVul Fix Pair: Authorization Bypass Through User-Controlled Key in php
**Pair ID:** 2845_3
**Vulnerability Class:** Insecure Direct Object Reference (IDOR)
**CWE:** CWE-639
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2845_3`)

## Vulnerability Information & PoC

## Description
Authorization Bypass Through User-Controlled Key - Retrieval of a user record occurs in the system based on some key value that is under user control.

## Vulnerable Code
```php
Lines 138-158 of the vulnerable file.

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
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -155,4 +155,94 @@
 
         return $subtask;
     }
+
+    protected function getColumn(array $project)
+    {
+        $column = $this->columnModel->getById($this->request->getIntegerParam('column_id'));
+
+        if (empty($column)) {
+            throw new PageNotFoundException();
+        }
+
+        if ($column['project_id'] != $project['id']) {
+            throw new AccessForbiddenException();
+        }
+
+        return $column;
+    }
+
+    protected function getSwimlane(array $project)
+    {
+        $swimlane = $this->swimlaneModel->getById($this->request->getIntegerParam('swimlane_id'));
+
+        if (empty($swimlane)) {
+            throw new PageNotFoundException();
+        }
+
+        if ($swimlane['project_id'] != $project['id']) {
+            throw new AccessForbiddenException();
+        }
+
+        return $swimlane;
+    }
+
+    protected function getCategory(array $project)
+    {
+        $category = $this->categoryModel->getById($this->request->getIntegerParam('category_id'));
+
+        if (empty($category)) {
+            throw new PageNotFoundException();
+        }
+
+        if ($category['project_id'] != $project['id']) {
+            throw new AccessForbiddenException();
+        }
+
+        return $category;
+    }
+
+    protected function getProjectTag(array $project)
+    {
+        $tag = $this->tagModel->getById($this->request->getIntegerParam('tag_id'));
+
+        if (empty($tag)) {
+            throw new PageNotFoundException();
+        }
+
+        if ($tag['project_id'] != $project['id']) {
+            throw new AccessForbiddenException();
+        }
+
+        return $tag;
+    }
+
+    protected function getAction(array $project)
+    {
+        $action = $this->actionModel->getById($this->request->getIntegerParam('action_id'));
+
+        if (empty($action)) {
+            throw new PageNotFoundException();
+        }
+
+        if ($action['project_id'] != $project['id']) {
+            throw new AccessForbiddenException();
+        }
+
+        return $action;
+    }
+
+    protected function getCustomFilter(array $project)
+    {
+        $filter = $this->customFilterModel->getById($this->request->getIntegerParam('filter_id'));
+
+        if (empty($filter)) {
+            throw new PageNotFoundException();
+        }
+
+        if ($filter['project_id'] != $project['id']) {
+            throw new AccessForbiddenException();
+        }
+
+        return $filter;
+    }
 }
```
