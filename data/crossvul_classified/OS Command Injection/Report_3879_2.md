# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in php
**Pair ID:** 3879_2
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3879_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```php
Lines 140-180 of the vulnerable file.

        }
        $this->set('_serialize', ['all_commands']);
        $this->set(compact(['all_commands']));
    }

    public function view($id = null) {
        if (!$this->isApiRequest()) {
            throw new MethodNotAllowedException();

        }
        if (!$this->Command->exists($id)) {
            throw new NotFoundException(__('Invalid command'));
        }
        $command = $this->Command->findById($id);
        $this->set('command', $command);
        $this->set('_serialize', ['command']);
    }

    public function add() {
        $userId = $this->Auth->user('id');
        $this->Frontend->setJson('console_welcome', $this->Command->getConsoleWelcome($this->systemname));
        $this->set('command_types', $this->getCommandTypes());

        if ($this->request->is('post') || $this->request->is('put')) {
            $this->request->data['Command']['uuid'] = UUID::v4();
            $this->request->data = $this->rewritePostData();

            if ($this->Command->saveAll($this->request->data)) {
                $changeLogData = $this->Changelog->parseDataForChangelog(
                    $this->params['action'],
                    $this->params['controller'],
                    $this->Command->id,
                    OBJECT_COMMAND,
                    [ROOT_CONTAINER],
                    $userId,
                    $this->request->data['Command']['name'],
                    $this->request->data
                );
                if ($changeLogData) {
                    CakeLog::write('log', serialize($changeLogData));
                }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -157,7 +157,6 @@
 
     public function add() {
         $userId = $this->Auth->user('id');
-        $this->Frontend->setJson('console_welcome', $this->Command->getConsoleWelcome($this->systemname));
         $this->set('command_types', $this->getCommandTypes());
 
         if ($this->request->is('post') || $this->request->is('put')) {
@@ -210,7 +209,6 @@
             $command_types = $this->getCommandTypes();
             $this->set(compact(['command', 'command_types']));
             $this->set('_serialize', ['command', 'command_types']);
-            $this->Frontend->setJson('console_welcome', $this->Command->getConsoleWelcome($this->systemname));
             $this->Frontend->setJson('command_id', $id);
 
             if ($this->request->is('post') || $this->request->is('put')) {
```
