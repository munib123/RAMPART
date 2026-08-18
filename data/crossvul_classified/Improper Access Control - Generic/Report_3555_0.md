# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in php
**Pair ID:** 3555_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3555_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```php
Lines 674-714 of the vulnerable file.

					$this->PasswordExpiry = date('Y-m-d', time() + 86400 * self::$password_expiry_days);
				} else {
					$this->PasswordExpiry = null;
				}
			}
		}

		// save locale
		if(!$this->Locale) {
			$this->Locale = i18n::get_locale();
		}
		
		parent::onBeforeWrite();
	}
	
	function onAfterWrite() {
		parent::onAfterWrite();

		if($this->isChanged('Password')) {
			MemberPassword::log($this);
		}
	}


	/**
	 * Check if the member is in one of the given groups.
	 *
	 * @param array|DataObjectSet $groups Collection of {@link Group} DataObjects to check
	 * @param boolean $strict Only determine direct group membership if set to true (Default: false)
	 * @return bool Returns TRUE if the member is in one of the given groups, otherwise FALSE.
	 */
	public function inGroups($groups, $strict = false) {
		if($groups) foreach($groups as $group) {
			if($this->inGroup($group, $strict)) return true;
		}
		
		return false;
	}


	/**
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -693,6 +693,24 @@
 			MemberPassword::log($this);
 		}
 	}
+	
+	/**
+	 * If any admin groups are requested, deny the whole save operation.
+	 * 
+	 * @param Array $ids Database IDs of Group records
+	 * @return boolean
+	 */
+	function onChangeGroups($ids) {
+		// Filter out admin groups to avoid privilege escalation, 
+		// unless the current user is an admin already
+		if(!Permission::checkMember($this, 'ADMIN')) {
+			$adminGroups = Permission::get_groups_by_permission('ADMIN');
+			$adminGroupIDs = ($adminGroups) ? $adminGroups->column('ID') : array();
+			return count(array_intersect($ids, $adminGroupIDs)) == 0;
+		} else {
+			return true;
+		}
+	}
 
 
 	/**
```
