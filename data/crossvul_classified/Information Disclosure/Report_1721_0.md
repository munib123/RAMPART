# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 1721_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1721_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 460-500 of the vulnerable file.

	 * @param User $userObj User object for the target
	 * @return string Appropriately-escaped HTML to be output literally
	 * @todo FIXME: Almost the same as contributionsSub in SpecialContributions.php. Could be combined.
	 */
	function getSubTitle( $userObj ) {
		if ( $userObj->isAnon() ) {
			$user = htmlspecialchars( $userObj->getName() );
		} else {
			$user = Linker::link( $userObj->getUserPage(), htmlspecialchars( $userObj->getName() ) );
		}
		$links = '';
		$nt = $userObj->getUserPage();
		$id = $userObj->getID();
		$talk = $nt->getTalkPage();
		if ( $talk ) {
			# Talk page link
			$tools[] = Linker::link( $talk, $this->msg( 'sp-contributions-talk' )->escaped() );
			if ( ( $id !== null ) || ( $id === null && IP::isIPAddress( $nt->getText() ) ) ) {
				# Block / Change block / Unblock links
				if ( $this->getUser()->isAllowed( 'block' ) ) {
					if ( $userObj->isBlocked() ) {
						$tools[] = Linker::linkKnown( # Change block link
							SpecialPage::getTitleFor( 'Block', $nt->getDBkey() ),
							$this->msg( 'change-blocklink' )->escaped()
						);
						$tools[] = Linker::linkKnown( # Unblock link
							SpecialPage::getTitleFor( 'BlockList' ),
							$this->msg( 'unblocklink' )->escaped(),
							array(),
							array(
								'action' => 'unblock',
								'ip' => $nt->getDBkey()
							)
						);
					} else {
						# User is not blocked
						$tools[] = Linker::linkKnown( # Block link
							SpecialPage::getTitleFor( 'Block', $nt->getDBkey() ),
							$this->msg( 'blocklink' )->escaped()
						);
					}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -477,7 +477,7 @@
 			if ( ( $id !== null ) || ( $id === null && IP::isIPAddress( $nt->getText() ) ) ) {
 				# Block / Change block / Unblock links
 				if ( $this->getUser()->isAllowed( 'block' ) ) {
-					if ( $userObj->isBlocked() ) {
+					if ( $userObj->isBlocked() && $userObj->getBlock()->getType() !== Block::TYPE_AUTO ) {
 						$tools[] = Linker::linkKnown( # Change block link
 							SpecialPage::getTitleFor( 'Block', $nt->getDBkey() ),
 							$this->msg( 'change-blocklink' )->escaped()
```
