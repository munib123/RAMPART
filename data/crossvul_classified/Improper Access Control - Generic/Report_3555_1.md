# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in php
**Pair ID:** 3555_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3555_1`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```php
Lines 510-550 of the vulnerable file.

		$this->assertEquals('Test', $member->getName());
	}
	
	function testMembersWithSecurityAdminAccessCantEditAdminsUnlessTheyreAdminsThemselves() {
		$adminMember = $this->objFromFixture('Member', 'admin');
		$otherAdminMember = $this->objFromFixture('Member', 'other-admin');
		$securityAdminMember = $this->objFromFixture('Member', 'test');
		$ceoMember = $this->objFromFixture('Member', 'ceomember');
		
		// Careful: Don't read as english language.
		// More precisely this should read canBeEditedBy()
		
		$this->assertTrue($adminMember->canEdit($adminMember), 'Admins can edit themselves');
		$this->assertTrue($otherAdminMember->canEdit($adminMember), 'Admins can edit other admins');
		$this->assertTrue($securityAdminMember->canEdit($adminMember), 'Admins can edit other members');
		
		$this->assertTrue($securityAdminMember->canEdit($securityAdminMember), 'Security-Admins can edit themselves');
		$this->assertFalse($adminMember->canEdit($securityAdminMember), 'Security-Admins can not edit other admins');
		$this->assertTrue($ceoMember->canEdit($securityAdminMember), 'Security-Admins can edit other members');
	}

	/**
	 * Add the given array of member extensions as class names.
	 * This is useful for re-adding extensions after being removed
	 * in a test case to produce an unbiased test.
	 * 
	 * @param array $extensions
	 * @return array The added extensions
	 */
	protected function addExtensions($extensions) {
		if($extensions) foreach($extensions as $extension) {
			Object::add_extension('Member', $extension);
		}
		return $extensions;
	}

	/**
	 * Remove given extensions from Member. This is useful for
	 * removing extensions that could produce a biased
	 * test result, as some extensions applied by project
	 * code or modules can do this.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -527,6 +527,35 @@
 		$this->assertFalse($adminMember->canEdit($securityAdminMember), 'Security-Admins can not edit other admins');
 		$this->assertTrue($ceoMember->canEdit($securityAdminMember), 'Security-Admins can edit other members');
 	}
+	
+	function testOnChangeGroups() {
+		$staffGroup = $this->objFromFixture('Group', 'staffgroup');
+		$adminGroup = $this->objFromFixture('Group', 'admingroup');
+		$staffMember = $this->objFromFixture('Member', 'staffmember');
+		$adminMember = $this->objFromFixture('Member', 'admin');
+		$newAdminGroup = new Group(array('Title' => 'newadmin'));
+		$newAdminGroup->write();
+		Permission::grant($newAdminGroup->ID, 'ADMIN');
+		$newOtherGroup = new Group(array('Title' => 'othergroup'));
+		$newOtherGroup->write();
+		
+		$this->assertTrue(
+			$staffMember->onChangeGroups(array($staffGroup->ID)),
+			'Adding existing non-admin group relation is allowed for non-admin members'
+		);
+		$this->assertTrue(
+			$staffMember->onChangeGroups(array($newOtherGroup->ID)),
+			'Adding new non-admin group relation is allowed for non-admin members'
+		);
+		$this->assertFalse(
+			$staffMember->onChangeGroups(array($newAdminGroup->ID)),
+			'Adding new admin group relation is not allowed for non-admin members'
+		);
+		$this->assertTrue(
+			$adminMember->onChangeGroups(array($newAdminGroup->ID)),
+			'Adding new admin group relation is allowed for admin members'
+		);
+	}
 
 	/**
 	 * Add the given array of member extensions as class names.
```
