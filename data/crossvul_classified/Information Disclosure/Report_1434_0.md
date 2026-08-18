# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 1434_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1434_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 324-364 of the vulnerable file.

            // let's set the context to event here, since we reuse the variable later on for some additional lookups.
            // Passing $context = 'org' could have interesting results otherwise...
            $context = 'event';
            $object = $this->Event->fetchEvent($this->Auth->user(), $options = array('eventid' => $id, 'metadata' => true));
        }
        if (empty($object)) {
            throw new MethodNotAllowedException('Invalid object.');
        }
        $conditions = array(
            'Sighting.' . $context . '_id' => $id
        );
        if ($org_id) {
            $conditions[] = array('Sighting.org_id' => $org_id);
        }
        $sightings = $this->Sighting->find('all', array(
            'conditions' => $conditions,
            'recursive' => -1,
            'contain' => array('Organisation.name'),
            'order' => array('Sighting.date_sighting DESC')
        ));
        $this->set('org_id', $org_id);
        $this->set('rawId', $rawId);
        $this->set('context', $context);
        $this->set('types', array('Sighting', 'False-positive', 'Expiration'));
        if (Configure::read('Plugin.Sightings_anonymise') && !$this->_isSiteAdmin()) {
            foreach ($sightings as $k => $v) {
                if ($v['Sighting']['org_id'] != $this->Auth->user('org_id')) {
                    $sightings[$k]['Organisation']['name'] = '';
                    $sightings[$k]['Sighting']['org_id'] = 0;
                }
            }
        }
        if ($this->_isRest()) {
            return $this->RestResponse->viewData($sightings, $this->response->type());
        }
        $this->set('sightings', $sightings);
        $this->layout = false;
        $this->render('ajax/list_sightings');
    }

    public function viewSightings($id, $context = 'attribute')
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -341,22 +341,72 @@
             'contain' => array('Organisation.name'),
             'order' => array('Sighting.date_sighting DESC')
         ));
+        if (!empty($sightings) && empty(Configure::read('Plugin.Sightings_policy')) && !$this->_isSiteAdmin()) {
+            $eventOwnerOrgIdList = array();
+            foreach ($sightings as $k => $sighting) {
+                if (empty($eventOwnerOrgIdList[$sighting['Sighting']['event_id']])) {
+                    $temp_event = $this->Event->find('first', array(
+                        'recursive' => -1,
+                        'conditions' => array('Event.id' => $sighting['Sighting']['event_id']),
+                        'fields' => array('Event.id', 'Event.orgc_id')
+                    ));
+                    $eventOwnerOrgIdList[$temp_event['Event']['id']] = $temp_event['Event']['orgc_id'];
+                }
+                if (empty($eventOwnerOrgIdList[$sighting['Sighting']['event_id']]) || $eventOwnerOrgIdList[$sighting['Sighting']['event_id']] !== $this->Auth->user('org_id')) {
+                    unset($sightings[$k]);
+                }
+            }
+            $sightings = array_values($sightings);
+        } else if (!empty($sightings) && Configure::read('Plugin.Sightings_policy') == 1 && !$this->_isSiteAdmin()) {
+            $eventsWithOwnSightings = array();
+            foreach ($sightings as $k => $sighting) {
+                if (empty($eventsWithOwnSightings[$sighting['Sighting']['event_id']])) {
+                    $eventsWithOwnSightings[$sighting['Sighting']['event_id']] = false;
+                    $sighting_temp = $this->Sighting->find('first', array(
+                        'recursive' => -1,
+                        'conditions' => array(
+                            'Sighting.event_id' => $sighting['Sighting']['event_id'],
+                            'Sighting.org_id' => $this->Auth->user('org_id')
+                        )
+                    ));
+                    if (empty($sighting_temp)) {
+                        $temp_event = $this->Event->find('first', array(
+                            'recursive' => -1,
+                            'conditions' => array(
+                                'Event.id' => $sighting['Sighting']['event_id'],
+                                'Event.orgc_id' => $this->Auth->user('org_id')
+                            ),
+                            'fields' => array('Event.id', 'Event.orgc_id')
+                        ));
+                        $eventsWithOwnSightings[$sighting['Sighting']['event_id']] = !empty($temp_event);
+                    } else {
+                        $eventsWithOwnSightings[$sighting['Sighting']['event_id']] = true;
+                    }
+                }
+                if (!$eventsWithOwnSightings[$sighting['Sighting']['event_id']]) {
+                    unset($sightings[$k]);
+                }
+            }
+            $sightings = array_values($sightings);
+        }
         $this->set('org_id', $org_id);
         $this->set('rawId', $rawId);
         $this->set('context', $context);
         $this->set('types', array('Sighting', 'False-positive', 'Expiration'));
         if (Configure::read('Plugin.Sightings_anonymise') && !$this->_isSiteAdmin()) {
-            foreach ($sightings as $k => $v) {
-                if ($v['Sighting']['org_id'] != $this->Auth->user('org_id')) {
-                    $sightings[$k]['Organisation']['name'] = '';
-                    $sightings[$k]['Sighting']['org_id'] = 0;
+            if (!empty($sightings)) {
+                foreach ($sightings as $k => $v) {
+                    if ($v['Sighting']['org_id'] != $this->Auth->user('org_id')) {
+                        $sightings[$k]['Organisation']['name'] = '';
+                        $sightings[$k]['Sighting']['org_id'] = 0;
+                    }
                 }
             }
         }
         if ($this->_isRest()) {
             return $this->RestResponse->viewData($sightings, $this->response->type());
         }
-        $this->set('sightings', $sightings);
+        $this->set('sightings', empty($sightings) ? array() : $sightings);
         $this->layout = false;
         $this->render('ajax/list_sightings');
     }
```
