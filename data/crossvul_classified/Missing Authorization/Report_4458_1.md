# CrossVul Fix Pair: Missing Authorization in php
**Pair ID:** 4458_1
**Vulnerability Class:** Missing Authorization
**CWE:** CWE-862
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4458_1`)

## Vulnerability Information & PoC

## Description
Missing Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```php
Lines 78-98 of the vulnerable file.

            foreach ($tempCluster as $key => $value) {
                $tempCluster[$key]['galaxy_cluster_id'] = $oldCluster['GalaxyCluster']['id'];
            }
            $elementsToSave = array_merge($elementsToSave, $tempCluster);
        }
        $this->saveMany($elementsToSave);
    }

    public function captureElements($user, $elements, $clusterId)
    {
        $tempElements = array();
        foreach ($elements as $k => $element) {
            $tempElements[] = array(
                'key' => $element['key'],
                'value' => $element['value'],
                'galaxy_cluster_id' => $clusterId,
            );
        }
        $this->saveMany($tempElements);
    }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -95,4 +95,37 @@
         }
         $this->saveMany($tempElements);
     }
+
+    public function buildACLConditions($user)
+    {
+        $conditions = [];
+        if (!$user['Role']['perm_site_admin']) {
+            $conditions = $this->GalaxyCluster->buildConditions($user);
+        }
+        return $conditions;
+    }
+
+    public function buildClusterConditions($user, $clusterId)
+    {
+        return [
+            $this->buildACLConditions($user),
+            'GalaxyCluster.id' => $clusterId
+        ];
+    }
+
+    public function fetchElements(array $user, $clusterId)
+    {
+        $params = array(
+            'conditions' => $this->buildClusterConditions($user, $clusterId),
+            'contain' => ['GalaxyCluster' => ['fields' => ['id', 'distribution', 'org_id']]],
+            'recursive' => -1
+        );
+        $elements = $this->find('all', $params);
+        foreach ($elements as $i => $element) {
+            $elements[$i] = $elements[$i]['GalaxyElement'];
+            unset($elements[$i]['GalaxyCluster']);
+            unset($elements[$i]['GalaxyElement']);
+        }
+        return $elements;
+    }
 }
```
