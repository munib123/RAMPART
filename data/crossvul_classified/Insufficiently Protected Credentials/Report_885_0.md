# CrossVul Fix Pair: Credentials Management Errors in php
**Pair ID:** 885_0
**Vulnerability Class:** Insufficiently Protected Credentials
**CWE:** CWE-255
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `885_0`)

## Vulnerability Information & PoC

## Description
Credentials Management Errors

## Vulnerable Code
```php
Lines 326-366 of the vulnerable file.

                $this->set('emailSearch', $filters['email']);
                $this->set('orgSearch', $filters['org']);
                $this->set('actionSearch', $filters['action']);
                $this->set('modelSearch', $filters['model']);
                $this->set('model_idSearch', $filters['model_id']);
                $this->set('titleSearch', $filters['title']);
                $this->set('changeSearch', $filters['change']);
                if (Configure::read('MISP.log_client_ip')) {
                    $this->set('ipSearch', $filters['ip']);
                }
                $this->set('isSearch', 1);

                // search the db
                $conditions = $this->__buildSearchConditions($filters);
                $this->{$this->defaultModel}->recursive = 0;
                $this->paginate = array(
                    'limit' => 60,
                    'conditions' => $conditions,
                    'order' => array('Log.id' => 'DESC')
                );
                $this->set('list', $this->paginate());

                // and store into session
                $this->Session->write('paginate_conditions_log', $this->paginate);
                $this->Session->write('paginate_conditions_log_email', $filters['email']);
                $this->Session->write('paginate_conditions_log_org', $filters['org']);
                $this->Session->write('paginate_conditions_log_action', $filters['action']);
                $this->Session->write('paginate_conditions_log_model', $filters['model']);
                $this->Session->write('paginate_conditions_log_model_id', $filters['model_id']);
                $this->Session->write('paginate_conditions_log_title', $filters['title']);
                $this->Session->write('paginate_conditions_log_change', $filters['change']);
                if (Configure::read('MISP.log_client_ip')) {
                    $this->Session->write('paginate_conditions_log_ip', $filters['ip']);
                }

                // set the same view as the index page
                $this->render('admin_index');
            } else {
                // get from Session
                $filters['email'] = $this->Session->read('paginate_conditions_log_email');
                $filters['org'] = $this->Session->read('paginate_conditions_log_org');
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -343,7 +343,11 @@
                     'conditions' => $conditions,
                     'order' => array('Log.id' => 'DESC')
                 );
-                $this->set('list', $this->paginate());
+                $list = $this->paginate();
+                if (empty($this->Auth->user('Role')['perm_site_admin'])) {
+                    $list = $this->Log->filterSiteAdminSensitiveLogs($list);
+                }
+                $this->set('list', $list);
 
                 // and store into session
                 $this->Session->write('paginate_conditions_log', $this->paginate);
@@ -394,7 +398,11 @@
                 }
                 $conditions = $this->__buildSearchConditions($filters);
                 $this->paginate['conditions'] = $conditions;
-                $this->set('list', $this->paginate());
+                $list = $this->paginate();
+                if (empty($this->Auth->user('Role')['perm_site_admin'])) {
+                    $list = $this->Log->filterSiteAdminSensitiveLogs($list);
+                }
+                $this->set('list', $list);
 
                 // set the same view as the index page
                 $this->render('admin_index');
```
