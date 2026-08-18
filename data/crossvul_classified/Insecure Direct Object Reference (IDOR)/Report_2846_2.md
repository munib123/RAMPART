# CrossVul Fix Pair: Authorization Bypass Through User-Controlled Key in php
**Pair ID:** 2846_2
**Vulnerability Class:** Insecure Direct Object Reference (IDOR)
**CWE:** CWE-639
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2846_2`)

## Vulnerability Information & PoC

## Description
Authorization Bypass Through User-Controlled Key - Retrieval of a user record occurs in the system based on some key value that is under user control.

## Vulnerable Code
```php
Lines 49-89 of the vulnerable file.

    {
        $values = array(
            'task_id' => $task['id'],
            'user_id' => $task['owner_id'],
            'another_subtask' => $this->request->getIntegerParam('another_subtask', 0)
        );

        $values = $this->hook->merge('controller:subtask:form:default', $values, array('default_values' => $values));
        return $values;
    }

    /**
     * Validation and creation
     *
     * @access public
     */
    public function save()
    {
        $task = $this->getTask();
        $values = $this->request->getValues();

        list($valid, $errors) = $this->subtaskValidator->validateCreation($values);

        if ($valid) {
            if ($this->subtaskModel->create($values) !== false) {
                $this->flash->success(t('Sub-task added successfully.'));
            } else {
                $this->flash->failure(t('Unable to create your sub-task.'));
            }

            if (isset($values['another_subtask']) && $values['another_subtask'] == 1) {
                return $this->create(array(
                    'project_id' => $task['project_id'],
                    'task_id' => $task['id'],
                    'user_id' => $values['user_id'],
                    'another_subtask' => 1
                ));
            }

            return $this->response->redirect($this->helper->url->to('TaskViewController', 'show', array('project_id' => $task['project_id'], 'task_id' => $task['id']), 'subtasks'), true);
        }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -66,6 +66,7 @@
     {
         $task = $this->getTask();
         $values = $this->request->getValues();
+        $values['task_id'] = $task['id'];
 
         list($valid, $errors) = $this->subtaskValidator->validateCreation($values);
 
@@ -103,7 +104,7 @@
     public function edit(array $values = array(), array $errors = array())
     {
         $task = $this->getTask();
-        $subtask = $this->getSubtask();
+        $subtask = $this->getSubtask($task);
 
         $this->response->html($this->template->render('subtask/edit', array(
             'values' => empty($values) ? $subtask : $values,
@@ -123,9 +124,12 @@
     public function update()
     {
         $task = $this->getTask();
-        $this->getSubtask();
+        $subtask = $this->getSubtask($task);
 
         $values = $this->request->getValues();
+        $values['id'] = $subtask['id'];
+        $values['task_id'] = $task['id'];
+
         list($valid, $errors) = $this->subtaskValidator->validateModification($values);
 
         if ($valid) {
@@ -149,7 +153,7 @@
     public function confirm()
     {
         $task = $this->getTask();
-        $subtask = $this->getSubtask();
+        $subtask = $this->getSubtask($task);
 
         $this->response->html($this->template->render('subtask/remove', array(
             'subtask' => $subtask,
@@ -166,7 +170,7 @@
     {
         $this->checkCSRFParam();
         $task = $this->getTask();
-        $subtask = $this->getSubtask();
+        $subtask = $this->getSubtask($task);
 
         if ($this->subtaskModel->remove($subtask['id'])) {
             $this->flash->success(t('Sub-task removed successfully.'));
```
