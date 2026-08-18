# CrossVul Fix Pair: Authorization Bypass Through User-Controlled Key in php
**Pair ID:** 2845_2
**Vulnerability Class:** Insecure Direct Object Reference (IDOR)
**CWE:** CWE-639
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2845_2`)

## Vulnerability Information & PoC

## Description
Authorization Bypass Through User-Controlled Key - Retrieval of a user record occurs in the system based on some key value that is under user control.

## Vulnerable Code
```php
Lines 18-58 of the vulnerable file.

    public function create()
    {
        $project = $this->getProject();

        $this->response->html($this->template->render('action_creation/create', array(
            'project' => $project,
            'values' => array('project_id' => $project['id']),
            'available_actions' => $this->actionManager->getAvailableActions(),
        )));
    }

    /**
     * Choose the event according to the action (step 2)
     *
     * @access public
     */
    public function event()
    {
        $project = $this->getProject();
        $values = $this->request->getValues();

        if (empty($values['action_name']) || empty($values['project_id'])) {
            return $this->create();
        }

        return $this->response->html($this->template->render('action_creation/event', array(
            'values' => $values,
            'project' => $project,
            'available_actions' => $this->actionManager->getAvailableActions(),
            'events' => $this->actionManager->getCompatibleEvents($values['action_name']),
        )));
    }

    /**
     * Define action parameters (step 3)
     *
     * @access public
     */
    public function params()
    {
        $project = $this->getProject();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -35,8 +35,9 @@
     {
         $project = $this->getProject();
         $values = $this->request->getValues();
+        $values['project_id'] = $project['id'];
 
-        if (empty($values['action_name']) || empty($values['project_id'])) {
+        if (empty($values['action_name'])) {
             return $this->create();
         }
 
@@ -57,8 +58,9 @@
     {
         $project = $this->getProject();
         $values = $this->request->getValues();
+        $values['project_id'] = $project['id'];
 
-        if (empty($values['action_name']) || empty($values['project_id']) || empty($values['event_name'])) {
+        if (empty($values['action_name']) || empty($values['event_name'])) {
             $this->create();
             return;
         }
@@ -109,6 +111,7 @@
      */
     private function doCreation(array $project, array $values)
     {
+        $values['project_id'] = $project['id'];
         list($valid, ) = $this->actionValidator->validateCreation($values);
 
         if ($valid) {
```
