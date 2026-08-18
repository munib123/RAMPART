# CrossVul Fix Pair: Improper Authorization in php
**Pair ID:** 5450_0
**Vulnerability Class:** Improper Authorization
**CWE:** CWE-285
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5450_0`)

## Vulnerability Information & PoC

## Description
Improper Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```php
Lines 223-263 of the vulnerable file.

		try {
			$share = $this->shareManager->getShareById('ocinternal:' . $id);
		} catch (ShareNotFound $e) {
			//Ignore for now
			//return new \OC_OCS_Result(null, 404, 'wrong share ID, share doesn\'t exist.');
		}

		// Could not find the share as internal share... maybe it is a federated share
		if ($share === null) {
			if (!$this->shareManager->outgoingServer2ServerSharesAllowed()) {
				return new \OC_OCS_Result(null, 404, 'wrong share ID, share doesn\'t exist.');
			}

			try {
				$share = $this->shareManager->getShareById('ocFederatedSharing:' . $id);
			} catch (ShareNotFound $e) {
				return new \OC_OCS_Result(null, 404, 'wrong share ID, share doesn\'t exist.');
			}
		}

		if (!$this->canAccessShare($share)) {
			return new \OC_OCS_Result(null, 404, 'could not delete share');
		}

		$this->shareManager->deleteShare($share);

		return new \OC_OCS_Result();
	}

	/**
	 * @return \OC_OCS_Result
	 */
	public function createShare() {
		$share = $this->shareManager->newShare();

		if (!$this->shareManager->shareApiEnabled()) {
			return new \OC_OCS_Result(null, 404, 'Share API is disabled');
		}

		// Verify path
		$path = $this->request->getParam('path', null);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -240,7 +240,7 @@
 			}
 		}
 
-		if (!$this->canAccessShare($share)) {
+		if (!$this->canAccessShare($share, false)) {
 			return new \OC_OCS_Result(null, 404, 'could not delete share');
 		}
 
@@ -564,7 +564,7 @@
 			}
 		}
 
-		if (!$this->canAccessShare($share)) {
+		if (!$this->canAccessShare($share, false)) {
 			return new \OC_OCS_Result(null, 404, 'wrong share Id, share doesn\'t exist.');
 		}
 
@@ -669,9 +669,10 @@
 
 	/**
 	 * @param \OCP\Share\IShare $share
+	 * @param bool $checkGroups
 	 * @return bool
 	 */
-	protected function canAccessShare(\OCP\Share\IShare $share) {
+	protected function canAccessShare(\OCP\Share\IShare $share, $checkGroups = true) {
 		// A file with permissions 0 can't be accessed by us. So Don't show it
 		if ($share->getPermissions() === 0) {
 			return false;
@@ -690,7 +691,7 @@
 			return true;
 		}
 
-		if ($share->getShareType() === \OCP\Share::SHARE_TYPE_GROUP) {
+		if ($checkGroups && $share->getShareType() === \OCP\Share::SHARE_TYPE_GROUP) {
 			$sharedWith = $this->groupManager->get($share->getSharedWith());
 			if ($sharedWith->inGroup($this->currentUser)) {
 				return true;
```
