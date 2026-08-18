# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 2453_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2453_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 229-269 of the vulnerable file.

            }
            if (!in_array($this->request->data['Feed']['input_source'], array('network', 'local'))) {
                $this->request->data['Feed']['input_source'] = 'network';
            }
            if (!isset($this->request->data['Feed']['delete_local_file'])) {
                $this->request->data['Feed']['delete_local_file'] = 0;
            }
            $this->request->data['Feed']['settings'] = json_encode($this->request->data['Feed']['settings']);
            $this->request->data['Feed']['event_id'] = !empty($this->request->data['Feed']['fixed_event']) ? $this->request->data['Feed']['target_event'] : 0;
            if (!$error) {
                $result = $this->Feed->save($this->request->data);
                if ($result) {
                    $message = __('Feed added.');
                    if ($this->_isRest()) {
                        $feed = $this->Feed->find('first', array('conditions' => array('Feed.id' => $this->Feed->id), 'recursive' => -1));
                        return $this->RestResponse->viewData($feed, $this->response->type());
                    }
                    $this->Flash->success($message);
                    $this->redirect(array('controller' => 'feeds', 'action' => 'index'));
                } else {
                    $message = __('Feed could not be added. Invalid field: %s', array_keys($this->Feed->validationErrors)[0]);
                    if ($this->_isRest()) {
                        return $this->RestResponse->saveFailResponse('Feeds', 'add', false, $message, $this->response->type());
                    }
                    $this->Flash->error($message);
                    $this->request->data['Feed']['settings'] = json_decode($this->request->data['Feed']['settings'], true);
                }
            }
        } elseif ($this->_isRest()) {
            return $this->RestResponse->describe('Feeds', 'add', false, $this->response->type());
        }
    }

    private function __checkRegex($pattern)
    {
        if (@preg_match($pattern, null) === false) {
            return false;
        }
        return true;
    }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -246,7 +246,7 @@
                     $this->Flash->success($message);
                     $this->redirect(array('controller' => 'feeds', 'action' => 'index'));
                 } else {
-                    $message = __('Feed could not be added. Invalid field: %s', array_keys($this->Feed->validationErrors)[0]);
+                    $message = __('Feed could not be added. Reason: %s', json_encode($this->Feed->validationErrors));
                     if ($this->_isRest()) {
                         return $this->RestResponse->saveFailResponse('Feeds', 'add', false, $message, $this->response->type());
                     }
@@ -345,7 +345,7 @@
                 $this->Flash->success($message);
                 $this->redirect(array('controller' => 'feeds', 'action' => 'index'));
             } else {
-                $message = __('Feed could not be updated. Invalid fields: %s', implode(', ', array_keys($this->Feed->validationErrors)));
+                $message = __('Feed could not be updated. Reason: %s', json_encode($this->Feed->validationErrors));
                 if ($this->_isRest()) {
                     return $this->RestResponse->saveFailResponse('Feeds', 'add', false, $message, $this->response->type());
                 }
```
