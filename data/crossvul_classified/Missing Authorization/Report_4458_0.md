# CrossVul Fix Pair: Missing Authorization in php
**Pair ID:** 4458_0
**Vulnerability Class:** Missing Authorization
**CWE:** CWE-862
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4458_0`)

## Vulnerability Information & PoC

## Description
Missing Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```php
Lines 1-27 of the vulnerable file.

<?php
App::uses('AppController', 'Controller');

class GalaxyElementsController extends AppController
{
    public $components = array('Session', 'RequestHandler');

    public $paginate = array(
            'limit' => 20,
            'maxLimit' => 9999, // LATER we will bump here on a problem once we have more than 9999 events <- no we won't, this is the max a user van view/page.
            'recursive' => -1,
            'order' => array(
                'GalaxyElement.key' => 'ASC'
            )
    );

    public function index($id)
    {
        $this->paginate['conditions'] = array('GalaxyElement.galaxy_cluster_id' => $id);
        $clusters = $this->paginate();
        $this->set('list', $clusters);
        if ($this->request->is('ajax')) {
            $this->layout = 'ajax';
            $this->render('ajax/index');
        }
    }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -14,9 +14,11 @@
             )
     );
 
-    public function index($id)
+    public function index($clusterId)
     {
-        $this->paginate['conditions'] = array('GalaxyElement.galaxy_cluster_id' => $id);
+        $aclConditions = $this->GalaxyElement->buildClusterConditions($this->Auth->user(), $clusterId);
+        $this->paginate['conditions'] = [$aclConditions];
+        $this->paginate['contain'] = ['GalaxyCluster' => ['fields' => ['id', 'distribution', 'org_id']]];
         $clusters = $this->paginate();
         $this->set('list', $clusters);
         if ($this->request->is('ajax')) {
```
