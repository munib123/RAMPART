# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 4071_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4071_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 1628-1668 of the vulnerable file.

        // build the list of composite Attribute.type dynamically by checking if type contains a |
        // default composite types
        $compositeTypes = array('malware-sample');  // TODO hardcoded composite
        // dynamically generated list
        foreach (array_keys($this->typeDefinitions) as $type) {
            $pieces = explode('|', $type);
            if (2 == count($pieces)) {
                $compositeTypes[] = $type;
            }
        }
        return $compositeTypes;
    }

    public function isOwnedByOrg($attributeId, $org)
    {
        $this->id = $attributeId;
        $this->read();
        return $this->data['Event']['org_id'] === $org;
    }

    public function getRelatedAttributes($attribute, $fields=array(), $includeEventData = false)
    {
        // LATER getRelatedAttributes($attribute) this might become a performance bottleneck

        // exclude these specific categories from being linked
        switch ($attribute['category']) {
            case 'Antivirus detection':
                return null;
        }
        // exclude these specific types from being linked
        switch ($attribute['type']) {
            case 'other':
            case 'comment':
                return null;
        }

        // prepare the conditions
        $conditions = array(
                'Attribute.event_id !=' => $attribute['event_id'],
                );

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1645,7 +1645,7 @@
         return $this->data['Event']['org_id'] === $org;
     }
 
-    public function getRelatedAttributes($attribute, $fields=array(), $includeEventData = false)
+    public function getRelatedAttributes($user, $attribute, $fields=array(), $includeEventData = false)
     {
         // LATER getRelatedAttributes($attribute) this might become a performance bottleneck
 
@@ -1684,16 +1684,17 @@
                     'Attribute.value2' => array($attribute['value1'],$attribute['value2']),
             );
         }
-
+        $baseConditions = $this->buildConditions($user);
+        $baseConditions['AND'][] = $conditions;
         // do the search
         if (empty($fields)) {
             $fields = array('Attribute.*');
         }
         $params = array(
-            'conditions' => $conditions,
+            'conditions' => $baseConditions,
             'fields' => $fields,
             'recursive' => 0,
-            'group' => array('Attribute.event_id'),
+            'group' => array('Attribute.id', 'Attribute.event_id', 'Attribute.object_id', 'Attribute.object_relation', 'Attribute.category', 'Attribute.type', 'Attribute.value', 'Attribute.uuid', 'Attribute.timestamp', 'Attribute.distribution', 'Attribute.sharing_group_id', 'Attribute.to_ids', 'Attribute.comment', 'Event.id', 'Event.uuid', 'Event.threat_level_id', 'Event.analysis', 'Event.info', 'Event.extends_uuid', 'Event.distribution', 'Event.sharing_group_id', 'Event.published', 'Event.date', 'Event.orgc_id', 'Event.org_id', 'Object.id', 'Object.uuid', 'Object.distribution', 'Object.name', 'Object.template_uuid', 'Object.distribution', 'Object.sharing_group_id'),
             'order' => 'Attribute.event_id DESC'
         );
         if (!empty($includeEventData)) {
@@ -1701,6 +1702,11 @@
                 'Event' => array(
                     'fields' => array(
                         'Event.id', 'Event.uuid', 'Event.threat_level_id', 'Event.analysis', 'Event.info', 'Event.extends_uuid', 'Event.distribution', 'Event.sharing_group_id', 'Event.published', 'Event.date', 'Event.orgc_id', 'Event.org_id'
+                    )
+                ),
+                'Object' => array(
+                    'fields' => array(
+                        'Object.id', 'Object.uuid', 'Object.distribution', 'Object.name', 'Object.template_uuid', 'Object.distribution', 'Object.sharing_group_id'
                     )
                 )
             );
@@ -3436,7 +3442,7 @@
                 }
                 if (!empty($options['includeCorrelations'])) {
                     $attributeFields = array('id', 'event_id', 'object_id', 'object_relation', 'category', 'type', 'value', 'uuid', 'timestamp', 'distribution', 'sharing_group_id', 'to_ids', 'comment');
-                    $results[$k]['Attribute']['RelatedAttribute'] = ($this->getRelatedAttributes($results[$k]['Attribute'], $attributeFields, true));
+                    $results[$k]['Attribute']['RelatedAttribute'] = ($this->getRelatedAttributes($user, $results[$k]['Attribute'], $attributeFields, true));
                 }
             }
             if (!$loop) {
```
