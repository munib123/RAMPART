# CrossVul Fix Pair: Authorization Bypass Through User-Controlled Key in php
**Pair ID:** 2846_5
**Vulnerability Class:** Insecure Direct Object Reference (IDOR)
**CWE:** CWE-639
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2846_5`)

## Vulnerability Information & PoC

## Description
Authorization Bypass Through User-Controlled Key - Retrieval of a user record occurs in the system based on some key value that is under user control.

## Vulnerable Code
```php
Lines 1-41 of the vulnerable file.

<?php

namespace Kanboard\Controller;

/**
 * Subtask Status
 *
 * @package  Kanboard\Controller
 * @author   Frederic Guillot
 */
class SubtaskStatusController extends BaseController
{
    /**
     * Change status to the next status: Toto -> In Progress -> Done
     *
     * @access public
     */
    public function change()
    {
        $task = $this->getTask();
        $subtask = $this->getSubtask();
        $fragment = $this->request->getStringParam('fragment');

        $status = $this->subtaskStatusModel->toggleStatus($subtask['id']);
        $subtask['status'] = $status;

        if ($fragment === 'table') {
            $html = $this->renderTable($task);
        } elseif ($fragment === 'rows') {
            $html = $this->renderRows($task);
        } else {
            $html = $this->helper->subtask->renderToggleStatus($task, $subtask);
        }

        $this->response->html($html);
    }

    /**
     * Start/stop timer for subtasks
     *
     * @access public
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -18,7 +18,7 @@
     public function change()
     {
         $task = $this->getTask();
-        $subtask = $this->getSubtask();
+        $subtask = $this->getSubtask($task);
         $fragment = $this->request->getStringParam('fragment');
 
         $status = $this->subtaskStatusModel->toggleStatus($subtask['id']);
@@ -43,19 +43,19 @@
     public function timer()
     {
         $task = $this->getTask();
-        $subtaskId = $this->request->getIntegerParam('subtask_id');
+        $subtask = $this->getSubtask($task);
         $timer = $this->request->getStringParam('timer');
 
         if ($timer === 'start') {
-            $this->subtaskTimeTrackingModel->logStartTime($subtaskId, $this->userSession->getId());
+            $this->subtaskTimeTrackingModel->logStartTime($subtask['id'], $this->userSession->getId());
         } elseif ($timer === 'stop') {
-            $this->subtaskTimeTrackingModel->logEndTime($subtaskId, $this->userSession->getId());
+            $this->subtaskTimeTrackingModel->logEndTime($subtask['id'], $this->userSession->getId());
             $this->subtaskTimeTrackingModel->updateTaskTimeTracking($task['id']);
         }
 
         $this->response->html($this->template->render('subtask/timer', array(
             'task'    => $task,
-            'subtask' => $this->subtaskModel->getByIdWithDetails($subtaskId),
+            'subtask' => $this->subtaskModel->getByIdWithDetails($subtask['id']),
         )));
     }
 
```
