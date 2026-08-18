# CrossVul Fix Pair: Authorization Bypass Through User-Controlled Key in php
**Pair ID:** 2846_6
**Vulnerability Class:** Insecure Direct Object Reference (IDOR)
**CWE:** CWE-639
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2846_6`)

## Vulnerability Information & PoC

## Description
Authorization Bypass Through User-Controlled Key - Retrieval of a user record occurs in the system based on some key value that is under user control.

## Vulnerable Code
```php
Lines 57-97 of the vulnerable file.

                'dependencies' => $provider->getDependencies(),
                'errors' => array(),
                'task' => $task,
            )));

        } catch (ExternalLinkProviderNotFound $e) {
            $errors = array('text' => array(t('Unable to fetch link information.')));
            $this->find($values, $errors);
        }
    }

    /**
     * Save link
     *
     * @access public
     */
    public function save()
    {
        $task = $this->getTask();
        $values = $this->request->getValues();
        list($valid, $errors) = $this->externalLinkValidator->validateCreation($values);

        if ($valid) {
            if ($this->taskExternalLinkModel->create($values) !== false) {
                $this->flash->success(t('Link added successfully.'));
            } else {
                $this->flash->success(t('Unable to create your link.'));
            }

            $this->response->redirect($this->helper->url->to('TaskViewController', 'show', array('task_id' => $task['id'], 'project_id' => $task['project_id'])), true);
        } else {
            $provider = $this->externalLinkManager->getProvider($values['link_type']);
            $this->response->html($this->template->render('task_external_link/create', array(
                'values' => $values,
                'errors' => $errors,
                'dependencies' => $provider->getDependencies(),
                'task' => $task,
            )));
        }
    }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -74,6 +74,8 @@
     {
         $task = $this->getTask();
         $values = $this->request->getValues();
+        $values['task_id'] = $task['id'];
+
         list($valid, $errors) = $this->externalLinkValidator->validateCreation($values);
 
         if ($valid) {
@@ -108,22 +110,14 @@
     public function edit(array $values = array(), array $errors = array())
     {
         $task = $this->getTask();
-        $link_id = $this->request->getIntegerParam('link_id');
-
-        if ($link_id > 0) {
-            $values = $this->taskExternalLinkModel->getById($link_id);
-        }
-
-        if (empty($values)) {
-            throw new PageNotFoundException();
-        }
-
-        $provider = $this->externalLinkManager->getProvider($values['link_type']);
+        $link = $this->getExternalTaskLink($task);
+        $provider = $this->externalLinkManager->getProvider($link['link_type']);
 
         $this->response->html($this->template->render('task_external_link/edit', array(
-            'values' => $values,
-            'errors' => $errors,
-            'task' => $task,
+            'values'       => empty($values) ? $link : $values,
+            'errors'       => $errors,
+            'task'         => $task,
+            'link'         => $link,
             'dependencies' => $provider->getDependencies(),
         )));
     }
@@ -136,7 +130,12 @@
     public function update()
     {
         $task = $this->getTask();
+        $link = $this->getExternalTaskLink($task);
+
         $values = $this->request->getValues();
+        $values['id'] = $link['id'];
+        $values['task_id'] = $link['task_id'];
+
         list($valid, $errors) = $this->externalLinkValidator->validateModification($values);
 
         if ($valid && $this->taskExternalLinkModel->update($values)) {
@@ -155,12 +154,7 @@
     public function confirm()
     {
         $task = $this->getTask();
-        $link_id = $this->request->getIntegerParam('link_id');
-        $link = $this->taskExternalLinkModel->getById($link_id);
-
-        if (empty($link)) {
-            throw new PageNotFoundException();
-        }
+        $link = $this->getExternalTaskLink($task);
 
         $this->response->html($this->template->render('task_external_link/remove', array(
             'link' => $link,
@@ -177,8 +171,9 @@
     {
         $this->checkCSRFParam();
         $task = $this->getTask();
+        $link = $this->getExternalTaskLink($task);
 
-        if ($this->taskExternalLinkModel->remove($this->request->getIntegerParam('link_id'))) {
+        if ($this->taskExternalLinkModel->remove($link['id'])) {
             $this->flash->success(t('Link removed successfully.'));
         } else {
             $this->flash->failure(t('Unable to remove this link.'));
```
