# CrossVul Fix Pair: Authorization Bypass Through User-Controlled Key in php
**Pair ID:** 2846_4
**Vulnerability Class:** Insecure Direct Object Reference (IDOR)
**CWE:** CWE-639
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2846_4`)

## Vulnerability Information & PoC

## Description
Authorization Bypass Through User-Controlled Key - Retrieval of a user record occurs in the system based on some key value that is under user control.

## Vulnerable Code
```php
Lines 3-43 of the vulnerable file.

namespace Kanboard\Controller;

use Kanboard\Model\SubtaskModel;

/**
 * Subtask Restriction
 *
 * @package  Kanboard\Controller
 * @author   Frederic Guillot
 */
class SubtaskRestrictionController extends BaseController
{
    /**
     * Show popup
     *
     * @access public
     */
    public function show()
    {
        $task = $this->getTask();
        $subtask = $this->getSubtask();

        $this->response->html($this->template->render('subtask_restriction/show', array(
            'status_list' => array(
                SubtaskModel::STATUS_TODO => t('Todo'),
                SubtaskModel::STATUS_DONE => t('Done'),
            ),
            'subtask_inprogress' => $this->subtaskStatusModel->getSubtaskInProgress($this->userSession->getId()),
            'subtask' => $subtask,
            'task' => $task,
        )));
    }

    /**
     * Change status of the in progress subtask and the other subtask
     *
     * @access public
     */
    public function save()
    {
        $task = $this->getTask();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -20,7 +20,7 @@
     public function show()
     {
         $task = $this->getTask();
-        $subtask = $this->getSubtask();
+        $subtask = $this->getSubtask($task);
 
         $this->response->html($this->template->render('subtask_restriction/show', array(
             'status_list' => array(
@@ -41,7 +41,7 @@
     public function save()
     {
         $task = $this->getTask();
-        $subtask = $this->getSubtask();
+        $subtask = $this->getSubtask($task);
         $values = $this->request->getValues();
 
         // Change status of the previous "in progress" subtask
```
