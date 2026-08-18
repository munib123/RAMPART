# CrossVul Fix Pair: Improper Authorization in php
**Pair ID:** 5449_0
**Vulnerability Class:** Improper Authorization
**CWE:** CWE-285
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5449_0`)

## Vulnerability Information & PoC

## Description
Improper Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```php
Lines 207-247 of the vulnerable file.

	 * @param string $id
	 * @return \OC_OCS_Result
	 */
	public function deleteShare($id) {
		if (!$this->shareManager->shareApiEnabled()) {
			return new \OC_OCS_Result(null, 404, $this->l->t('Share API is disabled'));
		}

		try {
			$share = $this->getShareById($id);
		} catch (ShareNotFound $e) {
			return new \OC_OCS_Result(null, 404, $this->l->t('Wrong share ID, share doesn\'t exist'));
		}

		try {
			$share->getNode()->lock(ILockingProvider::LOCK_SHARED);
		} catch (LockedException $e) {
			return new \OC_OCS_Result(null, 404, 'could not delete share');
		}

		if (!$this->canAccessShare($share)) {
			$share->getNode()->unlock(ILockingProvider::LOCK_SHARED);
			return new \OC_OCS_Result(null, 404, $this->l->t('Could not delete share'));
		}

		$this->shareManager->deleteShare($share);

		$share->getNode()->unlock(ILockingProvider::LOCK_SHARED);

		return new \OC_OCS_Result();
	}

	/**
	 * @return \OC_OCS_Result
	 */
	public function createShare() {
		$share = $this->shareManager->newShare();

		if (!$this->shareManager->shareApiEnabled()) {
			return new \OC_OCS_Result(null, 404, $this->l->t('Share API is disabled'));
		}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -224,7 +224,7 @@
 			return new \OC_OCS_Result(null, 404, 'could not delete share');
 		}
 
-		if (!$this->canAccessShare($share)) {
+		if (!$this->canAccessShare($share, false)) {
 			$share->getNode()->unlock(ILockingProvider::LOCK_SHARED);
 			return new \OC_OCS_Result(null, 404, $this->l->t('Could not delete share'));
 		}
@@ -573,7 +573,7 @@
 
 		$share->getNode()->lock(\OCP\Lock\ILockingProvider::LOCK_SHARED);
 
-		if (!$this->canAccessShare($share)) {
+		if (!$this->canAccessShare($share, false)) {
 			$share->getNode()->unlock(ILockingProvider::LOCK_SHARED);
 			return new \OC_OCS_Result(null, 404, $this->l->t('Wrong share ID, share doesn\'t exist'));
 		}
@@ -703,7 +703,7 @@
 	 * @param \OCP\Share\IShare $share
 	 * @return bool
 	 */
-	protected function canAccessShare(\OCP\Share\IShare $share) {
+	protected function canAccessShare(\OCP\Share\IShare $share, $checkGroups = true) {
 		// A file with permissions 0 can't be accessed by us. So Don't show it
 		if ($share->getPermissions() === 0) {
 			return false;
@@ -722,7 +722,7 @@
 			return true;
 		}
 
-		if ($share->getShareType() === \OCP\Share::SHARE_TYPE_GROUP) {
+		if ($checkGroups && $share->getShareType() === \OCP\Share::SHARE_TYPE_GROUP) {
 			$sharedWith = $this->groupManager->get($share->getSharedWith());
 			if ($sharedWith->inGroup($this->currentUser)) {
 				return true;
```
