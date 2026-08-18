# CrossVul Fix Pair: Authorization Bypass Through User-Controlled Key in php
**Pair ID:** 2845_1
**Vulnerability Class:** Insecure Direct Object Reference (IDOR)
**CWE:** CWE-639
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2845_1`)

## Vulnerability Information & PoC

## Description
Authorization Bypass Through User-Controlled Key - Retrieval of a user record occurs in the system based on some key value that is under user control.

## Vulnerable Code
```php
Lines 29-69 of the vulnerable file.

            'available_params' => $this->actionManager->getAvailableParameters($actions),
            'columns_list' => $this->columnModel->getList($project['id']),
            'users_list' => $this->projectUserRoleModel->getAssignableUsersList($project['id']),
            'projects_list' => $this->projectUserRoleModel->getProjectsByUser($this->userSession->getId()),
            'colors_list' => $this->colorModel->getList(),
            'categories_list' => $this->categoryModel->getList($project['id']),
            'links_list' => $this->linkModel->getList(0, false),
            'swimlane_list' => $this->swimlaneModel->getList($project['id']),
            'title' => t('Automatic actions')
        )));
    }

    /**
     * Confirmation dialog before removing an action
     *
     * @access public
     */
    public function confirm()
    {
        $project = $this->getProject();

        $this->response->html($this->helper->layout->project('action/remove', array(
            'action' => $this->actionModel->getById($this->request->getIntegerParam('action_id')),
            'available_events' => $this->eventManager->getAll(),
            'available_actions' => $this->actionManager->getAvailableActions(),
            'project' => $project,
            'title' => t('Remove an action')
        )));
    }

    /**
     * Remove an action
     *
     * @access public
     */
    public function remove()
    {
        $this->checkCSRFParam();
        $project = $this->getProject();
        $action = $this->actionModel->getById($this->request->getIntegerParam('action_id'));

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -46,9 +46,10 @@
     public function confirm()
     {
         $project = $this->getProject();
+        $action = $this->getAction($project);
 
         $this->response->html($this->helper->layout->project('action/remove', array(
-            'action' => $this->actionModel->getById($this->request->getIntegerParam('action_id')),
+            'action' => $action,
             'available_events' => $this->eventManager->getAll(),
             'available_actions' => $this->actionManager->getAvailableActions(),
             'project' => $project,
@@ -65,7 +66,7 @@
     {
         $this->checkCSRFParam();
         $project = $this->getProject();
-        $action = $this->actionModel->getById($this->request->getIntegerParam('action_id'));
+        $action = $this->getAction($project);
 
         if (! empty($action) && $this->actionModel->remove($action['id'])) {
             $this->flash->success(t('Action removed successfully.'));
```
