# CrossVul Fix Pair: Improper Privilege Management in php
**Pair ID:** 4213_0
**Vulnerability Class:** Improper Privilege Management
**CWE:** CWE-269
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4213_0`)

## Vulnerability Information & PoC

## Description
Improper Privilege Management - The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Vulnerable Code
```php
Lines 1-25 of the vulnerable file.

<?php
App::uses('AppController', 'Controller');
App::uses('Xml', 'Utility');

class EventsController extends AppController
{
    public $components = array(
            'Security',
            'Email',
            'RequestHandler',
            'IOCImport',
            'Cidr'
    );

    public $paginate = array(
            'limit' => 60,
            'maxLimit' => 9999, // LATER we will bump here on a problem once we have more than 9999 events <- no we won't, this is the max a user van view/page.
            'order' => array(
                    'Event.timestamp' => 'DESC'
            ),
            'contain' => array(
                    'Org' => array('fields' => array('id', 'name', 'uuid')),
                    'Orgc' => array('fields' => array('id', 'name', 'uuid')),
                    'SharingGroup' => array('fields' => array('id', 'name', 'uuid'))
            )
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2,6 +2,9 @@
 App::uses('AppController', 'Controller');
 App::uses('Xml', 'Utility');
 
+/**
+ * @property Event $Event
+ */
 class EventsController extends AppController
 {
     public $components = array(
@@ -2792,9 +2795,8 @@
     // Users with a GnuPG key will get the mail encrypted, other users will get the mail unencrypted
     public function contact($id = null)
     {
-        $id = $this->Toolbox->findIdByUuid($this->Event, $id);
-        $this->Event->id = $id;
-        if (!$this->Event->exists()) {
+        $events = $this->Event->fetchEvent($this->Auth->user(), array('eventid' => $id));
+        if (empty($events)) {
             throw new NotFoundException(__('Invalid event'));
         }
         // User has filled in his contact form, send out the email.
@@ -2844,7 +2846,7 @@
         }
         // User didn't see the contact form yet. Present it to him.
         if (empty($this->data)) {
-            $this->data = $this->Event->read(null, $id);
+            $this->data = $events[0];
         }
     }
 
```
