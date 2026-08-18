# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 2847_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2847_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 57-97 of the vulnerable file.


        if ($project_id !== 0 && $project_id != $task['project_id']) {
            throw new AccessForbiddenException();
        }

        return $task;
    }

    /**
     * Get Task or Project file
     *
     * @access protected
     * @return array
     * @throws PageNotFoundException
     * @throws AccessForbiddenException
     */
    protected function getFile()
    {
        $task_id = $this->request->getIntegerParam('task_id');
        $file_id = $this->request->getIntegerParam('file_id');
        $model = 'projectFileModel';

        if ($task_id > 0) {
            $model = 'taskFileModel';
            $project_id = $this->taskFinderModel->getProjectId($task_id);

            if ($project_id !== $this->request->getIntegerParam('project_id')) {
                throw new AccessForbiddenException();
            }
        }

        $file = $this->$model->getById($file_id);

        if (empty($file)) {
            throw new PageNotFoundException();
        }

        $file['model'] = $model;
        return $file;
    }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -74,13 +74,14 @@
     {
         $task_id = $this->request->getIntegerParam('task_id');
         $file_id = $this->request->getIntegerParam('file_id');
+        $project_id = $this->request->getIntegerParam('project_id');
         $model = 'projectFileModel';
 
         if ($task_id > 0) {
             $model = 'taskFileModel';
-            $project_id = $this->taskFinderModel->getProjectId($task_id);
-
-            if ($project_id !== $this->request->getIntegerParam('project_id')) {
+            $task_project_id = $this->taskFinderModel->getProjectId($task_id);
+
+            if ($project_id != $task_project_id) {
                 throw new AccessForbiddenException();
             }
         }
@@ -89,6 +90,12 @@
 
         if (empty($file)) {
             throw new PageNotFoundException();
+        }
+
+        if (isset($file['task_id']) && $file['task_id'] != $task_id) {
+            throw new AccessForbiddenException();
+        } else if (isset($file['project_id']) && $file['project_id'] != $project_id) {
+            throw new AccessForbiddenException();
         }
 
         $file['model'] = $model;
```
