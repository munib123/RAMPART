# CrossVul Fix Pair: Improper Privilege Management in php
**Pair ID:** 4212_0
**Vulnerability Class:** Improper Privilege Management
**CWE:** CWE-269
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4212_0`)

## Vulnerability Information & PoC

## Description
Improper Privilege Management - The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Vulnerable Code
```php
Lines 332-374 of the vulnerable file.

            $fieldDesc['distribution'][$key] = $this->Attribute->distributionDescriptions[$key]['formdesc'];
        }
        foreach ($this->Attribute->categoryDefinitions as $key => $value) {
            $fieldDesc['category'][$key] = isset($value['formdesc']) ? $value['formdesc'] : $value['desc'];
        }
        foreach ($this->Attribute->typeDefinitions as $key => $value) {
            $fieldDesc['type'][$key] = isset($value['formdesc']) ? $value['formdesc'] : $value['desc'];
        }
        $this->loadModel('Noticelist');
        $notice_list_triggers = $this->Noticelist->getTriggerData();
        $this->set('notice_list_triggers', json_encode($notice_list_triggers, true));
        $this->set('fieldDesc', $fieldDesc);
        $this->set('typeDefinitions', $this->Attribute->typeDefinitions);
        $this->set('categoryDefinitions', $this->Attribute->categoryDefinitions);
        $this->set('published', $events['Event']['published']);
        $this->set('action', $this->action);
    }

    public function download($id = null)
    {
        $this->Attribute->id = $id;
        if (!$this->Attribute->exists()) {
            throw new NotFoundException(__('Invalid attribute'));
        }
        $this->Attribute->read();
        if (!$this->_isSiteAdmin() &&
            $this->Auth->user('org_id') !=
            $this->Attribute->data['Event']['org_id'] &&
            (
                $this->Attribute->data['Event']['distribution'] == 0 ||
                $this->Attribute->data['Attribute']['distribution'] == 0
            )) {
            throw new UnauthorizedException(__('You do not have the permission to view this event.'));
        }
        $this->__downloadAttachment($this->Attribute->data['Attribute']);
    }

    private function __downloadAttachment($attribute)
    {
        $attachments_dir = Configure::read('MISP.attachments_dir');
        if (empty($attachments_dir)) {
            $attachments_dir = $this->Attribute->getDefaultAttachments_dir();
        }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -349,21 +349,19 @@
 
     public function download($id = null)
     {
-        $this->Attribute->id = $id;
-        if (!$this->Attribute->exists()) {
-            throw new NotFoundException(__('Invalid attribute'));
-        }
-        $this->Attribute->read();
-        if (!$this->_isSiteAdmin() &&
-            $this->Auth->user('org_id') !=
-            $this->Attribute->data['Event']['org_id'] &&
-            (
-                $this->Attribute->data['Event']['distribution'] == 0 ||
-                $this->Attribute->data['Attribute']['distribution'] == 0
-            )) {
-            throw new UnauthorizedException(__('You do not have the permission to view this event.'));
-        }
-        $this->__downloadAttachment($this->Attribute->data['Attribute']);
+        if (is_numeric($id)) {
+            $conditions = array('Attribute.id' => $id);
+        } elseif (Validation::uuid($id)) {
+            $conditions = array('Attribute.uuid' => $id);
+        } else {
+            throw new NotFoundException(__('Invalid attribute id.'));
+        }
+        $conditions['Attribute.type'] = array('attachment', 'malware-sample');
+        $attributes = $this->Attribute->fetchAttributes($this->Auth->user(), array('conditions' => $conditions, 'flatten' => true));
+        if (empty($attributes)) {
+            throw new UnauthorizedException(__('Attribute does not exists or you do not have the permission to download this attribute.'));
+        }
+        $this->__downloadAttachment($attributes[0]['Attribute']);
     }
 
     private function __downloadAttachment($attribute)
@@ -2016,20 +2014,19 @@
         if (!$user) {
             throw new UnauthorizedException(__('This authentication key is not authorized to be used for exports. Contact your administrator.'));
         }
-        $this->Attribute->id = $id;
-        if (!$this->Attribute->exists()) {
-            throw new NotFoundException(__('Invalid attribute or no authorisation to view it.'));
-        }
-        $this->Attribute->read(null, $id);
-        if (!$user['User']['siteAdmin'] &&
-            $user['User']['org_id'] != $this->Attribute->data['Event']['org_id'] &&
-            (
-                $this->Attribute->data['Event']['distribution'] == 0 ||
-                $this->Attribute->data['Attribute']['distribution'] == 0
-            )) {
-            throw new NotFoundException(__('Invalid attribute or no authorisation to view it.'));
-        }
-        $this->__downloadAttachment($this->Attribute->data['Attribute']);
+        if (is_numeric($id)) {
+            $conditions = array('Attribute.id' => $id);
+        } elseif (Validation::uuid($id)) {
+            $conditions = array('Attribute.uuid' => $id);
+        } else {
+            throw new NotFoundException(__('Invalid attribute id.'));
+        }
+        $conditions['Attribute.type'] = array('attachment', 'malware-sample');
+        $attributes = $this->Attribute->fetchAttributes($user, array('conditions' => $conditions, 'flatten' => true));
+        if (empty($attributes)) {
+            throw new UnauthorizedException(__('Attribute does not exists or you do not have the permission to download this attribute.'));
+        }
+        $this->__downloadAttachment($attributes[0]['Attribute']);
     }
 
     public function text()
```
