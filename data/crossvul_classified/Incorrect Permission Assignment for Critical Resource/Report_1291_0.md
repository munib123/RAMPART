# CrossVul Fix Pair: Incorrect Permission Assignment for Critical Resource in php
**Pair ID:** 1291_0
**Vulnerability Class:** Incorrect Permission Assignment for Critical Resource
**CWE:** CWE-732
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1291_0`)

## Vulnerability Information & PoC

## Description
Incorrect Permission Assignment for Critical Resource - When a resource is given a permission setting that provides access to a wider range of actors than required, it could lead to the exposure of sensitive information, or the modification of that reso...

## Vulnerable Code
```php
Lines 843-883 of the vulnerable file.

            arsort($tags);
            arsort($taxonomies);
        }
        if ($percentage === 'true') {
            foreach ($tags as $tag => $count) {
                $tags[$tag] = round(100 * $count / $totalCount, 3) . '%';
            }
            foreach ($taxonomies as $taxonomy => $count) {
                $taxonomies[$taxonomy] = round(100 * $count / $totalCount, 3) . '%';
            }
        }
        $results = array('tags' => $tags, 'taxonomies' => $taxonomies);
        $this->autoRender = false;
        $this->layout = false;
        $this->set('data', $results);
        $this->set('flags', JSON_PRETTY_PRINT);
        $this->response->type('json');
        $this->render('/Servers/json/simple');
    }

    private function __findObjectByUuid($object_uuid, &$type)
    {
        $this->loadModel('Event');
        $object = $this->Event->find('first', array(
            'conditions' => array(
                'Event.uuid' => $object_uuid,
            ),
            'fields' => array('Event.orgc_id', 'Event.id'),
            'recursive' => -1
        ));
        $type = 'Event';
        if (!empty($object)) {
            if (
                !$this->_isSiteAdmin() &&
                !$this->userRole['perm_tagger'] &&
                $object['Event']['orgc_id'] != $this->Auth->user('org_id')
            ) {
                throw new MethodNotAllowedException('Invalid Target.');
            }
        } else {
            $type = 'Attribute';
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -860,41 +860,48 @@
         $this->render('/Servers/json/simple');
     }
 
-    private function __findObjectByUuid($object_uuid, &$type)
+    private function __findObjectByUuid($object_uuid, &$type, $scope = 'modify')
     {
         $this->loadModel('Event');
-        $object = $this->Event->find('first', array(
-            'conditions' => array(
-                'Event.uuid' => $object_uuid,
-            ),
-            'fields' => array('Event.orgc_id', 'Event.id'),
-            'recursive' => -1
+        if (!$this->userRole['perm_tagger']) {
+            throw new MethodNotAllowedException(__('This functionality requires tagging permission.'));
+        }
+        $object = $this->Event->fetchEvent($this->Auth->user(), array(
+            'event_uuid' => $object_uuid,
+            'metadata' => 1
         ));
         $type = 'Event';
         if (!empty($object)) {
+            $object = $object[0];
             if (
+                $scope !== 'view' &&
                 !$this->_isSiteAdmin() &&
-                !$this->userRole['perm_tagger'] &&
-                $object['Event']['orgc_id'] != $this->Auth->user('org_id')
+                !$object['Event']['orgc_id'] != $this->Auth->user('org_id')
             ) {
-                throw new MethodNotAllowedException('Invalid Target.');
+                throw new MethodNotAllowedException(__('Invalid Target.'));
             }
         } else {
             $type = 'Attribute';
-            $object = $this->Event->Attribute->find('first', array(
-                'conditions' => array(
-                    'Attribute.uuid' => $object_uuid,
-                ),
-                'fields' => array('Attribute.id'),
-                'recursive' => -1,
-                'contain' => array('Event.orgc_id')
-            ));
+            $object = $this->Event->Attribute->fetchAttributes(
+                $this->Auth->user(),
+                array(
+                    'conditions' => array(
+                        'Attribute.uuid' => $object_uuid
+                    ),
+                    'flatten' => 1
+                )
+            );
             if (!empty($object)) {
-                if (!$this->_isSiteAdmin() && !$this->userRole['perm_tagger'] && $object['Event']['orgc_id'] != $this->Auth->user('org_id')) {
-                    throw new MethodNotAllowedException('Invalid Target.');
-                }
-            } else {
-                throw new MethodNotAllowedException('Invalid Target.');
+                $object = $object[0];
+                if (
+                    $scope !== 'view' &&
+                    !$this->_isSiteAdmin() &&
+                    !$object['Event']['orgc_id'] != $this->Auth->user('org_id')
+                ) {
+                    throw new MethodNotAllowedException(__('Invalid Target.'));
+                }
+            } else {
+                throw new MethodNotAllowedException(__('Invalid Target.'));
             }
         }
         return $object;
@@ -932,11 +939,11 @@
                 $local = $this->request->data['local'];
             }
         }
-        if (!is_bool($local)) {
-            throw new InvalidArgumentException('Invalid local flag');
+        if (!empty($local) && $this->Auth->user('org_id') != Configure::read('MISP.host_org_id')) {
+            throw new MethodNotAllowedException(__('Local tags can only be added by users of the host organisation.'));
         }
         $objectType = '';
-        $object = $this->__findObjectByUuid($uuid, $objectType);
+        $object = $this->__findObjectByUuid($uuid, $objectType, $local ? 'view' : 'modify');
         $existingTag = $this->Tag->find('first', array('conditions' => $conditions, 'recursive' => -1));
         if (empty($existingTag)) {
             if (!is_numeric($tag)) {
@@ -1038,9 +1045,9 @@
             throw new MethodNotAllowedException('Invalid Tag.');
         }
         $objectType = '';
-        $object = $this->__findObjectByUuid($uuid, $objectType);
+        $object = $this->__findObjectByUuid($uuid, $objectType, 'view');
         if (empty($object)) {
-            throw new MethodNotAllowedException('Invalid Target.');
+            throw new MethodNotAllowedException(__('Invalid Target.'));
         }
         $connectorObject = $objectType . 'Tag';
         $this->loadModel($objectType);
@@ -1052,6 +1059,14 @@
         ));
         if (empty($existingAssociation)) {
             throw new MethodNotAllowedException('Could not remove tag as it is not attached to the target ' . $objectType);
+        } else {
+            if (empty($existingAssociation[$objectType . 'Tag']['local'])) {
+                $object = $this->__findObjectByUuid($uuid, $objectType);
+            } else {
+                if ($object['Event']['orgc_id'] !== $this->Auth->user('org_id') && $this->Auth->user('org_id') != Configure::read('MISP.host_org_id')) {
+                    throw new MethodNotAllowedException(__('Insufficient privileges to remove local tags from events you do not own.'));
+                }
+            }
         }
         $result = $this->$objectType->$connectorObject->delete($existingAssociation[$connectorObject]['id']);
         if ($result) {
```
