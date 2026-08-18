# CrossVul Fix Pair: Insertion of Sensitive Information into Log File in php
**Pair ID:** 2950_0
**Vulnerability Class:** Insertion of Sensitive Information into Log File
**CWE:** CWE-532
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2950_0`)

## Vulnerability Information & PoC

## Description
Insertion of Sensitive Information into Log File - While logging all information may be helpful during development stages, it is important that logging levels be set appropriately before a product ships so that sensitive user data and system inform...

## Vulnerable Code
```php
Lines 627-667 of the vulnerable file.

								$newValueStr = '';
								$cP = 0;
								foreach ($newValue as $newValuePart) {
									if ($cP < 2) $newValueStr .= '-' . $newValuePart;
									else $newValueStr = $newValuePart . $newValueStr;
									$cP++;
								}
								array_push($fieldsNewValues, $newValueStr);
							} else {
								array_push($fieldsNewValues, $newValue);
							}
						} else {
							array_push($fieldsNewValues, $this->data['User']['password']);
						}
					}
					// compare
					$fieldsResultStr = '';
					$c = 0;
					foreach ($fields as $field) {
						if (isset($fieldsOldValues[$c]) && $fieldsOldValues[$c] != $fieldsNewValues[$c]) {
							if ($field != 'confirm_password') {
								$fieldsResultStr = $fieldsResultStr . ', ' . $field . ' (' . $fieldsOldValues[$c] . ') => (' . $fieldsNewValues[$c] . ')';
							}
						}
						$c++;
					}
					$fieldsResultStr = substr($fieldsResultStr, 2);
					$this->__extralog("edit", "user", $fieldsResultStr);	// TODO Audit, check: modify User
					// TODO Audit, __extralog, fields compare END
					if ($this->_isRest()) {
						$user = $this->User->find('first', array(
								'conditions' => array('User.id' => $this->User->id),
								'recursive' => -1
						));
						$user['User']['password'] = '******';
						return $this->RestResponse->viewData($user, $this->response->type());
					} else {
						$this->Session->setFlash(__('The user has been saved'));
						$this->_refreshAuth(); // in case we modify ourselves
						$this->redirect(array('action' => 'index'));
					}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -644,7 +644,7 @@
 					$c = 0;
 					foreach ($fields as $field) {
 						if (isset($fieldsOldValues[$c]) && $fieldsOldValues[$c] != $fieldsNewValues[$c]) {
-							if ($field != 'confirm_password') {
+							if ($field != 'confirm_password' && $field != 'enable_password') {
 								$fieldsResultStr = $fieldsResultStr . ', ' . $field . ' (' . $fieldsOldValues[$c] . ') => (' . $fieldsNewValues[$c] . ')';
 							}
 						}
```
