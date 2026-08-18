# CrossVul Fix Pair: Authorization Bypass Through User-Controlled Key in php
**Pair ID:** 2846_3
**Vulnerability Class:** Insecure Direct Object Reference (IDOR)
**CWE:** CWE-639
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2846_3`)

## Vulnerability Information & PoC

## Description
Authorization Bypass Through User-Controlled Key - Retrieval of a user record occurs in the system based on some key value that is under user control.

## Vulnerable Code
```php
Lines 1-36 of the vulnerable file.

<?php

namespace Kanboard\Controller;

/**
 * Class SubtaskConverterController
 *
 * @package Kanboard\Controller
 * @author  Frederic Guillot
 */
class SubtaskConverterController extends BaseController
{
    public function show()
    {
        $task = $this->getTask();
        $subtask = $this->getSubtask();

        $this->response->html($this->template->render('subtask_converter/show', array(
            'subtask' => $subtask,
            'task' => $task,
        )));
    }

    public function save()
    {
        $project = $this->getProject();
        $subtask = $this->getSubtask();

        $task_id = $this->subtaskTaskConversionModel->convertToTask($project['id'], $subtask['id']);

        if ($task_id !== false) {
            $this->flash->success(t('Subtask converted to task successfully.'));
        } else {
            $this->flash->failure(t('Unable to convert the subtask.'));
        }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -13,7 +13,7 @@
     public function show()
     {
         $task = $this->getTask();
-        $subtask = $this->getSubtask();
+        $subtask = $this->getSubtask($task);
 
         $this->response->html($this->template->render('subtask_converter/show', array(
             'subtask' => $subtask,
@@ -24,7 +24,8 @@
     public function save()
     {
         $project = $this->getProject();
-        $subtask = $this->getSubtask();
+        $task = $this->getTask();
+        $subtask = $this->getSubtask($task);
 
         $task_id = $this->subtaskTaskConversionModel->convertToTask($project['id'], $subtask['id']);
 
```
