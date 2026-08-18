# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 5864_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5864_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 281-321 of the vulnerable file.


		return $this->msg( 'contribsub2' )->rawParams( $user, $links );
	}

	/**
	 * Links to different places.
	 * @param $userpage Title: Target user page
	 * @param $talkpage Title: Talk page
	 * @param $target User: Target user object
	 * @return array
	 */
	public function getUserLinks( Title $userpage, Title $talkpage, User $target ) {

		$id = $target->getId();
		$username = $target->getName();

		$tools[] = Linker::link( $talkpage, $this->msg( 'sp-contributions-talk' )->escaped() );

		if ( ( $id !== null ) || ( $id === null && IP::isIPAddress( $username ) ) ) {
			if ( $this->getUser()->isAllowed( 'block' ) ) { # Block / Change block / Unblock links
				if ( $target->isBlocked() ) {
					$tools[] = Linker::linkKnown( # Change block link
						SpecialPage::getTitleFor( 'Block', $username ),
						$this->msg( 'change-blocklink' )->escaped()
					);
					$tools[] = Linker::linkKnown( # Unblock link
						SpecialPage::getTitleFor( 'Unblock', $username ),
						$this->msg( 'unblocklink' )->escaped()
					);
				} else { # User is not blocked
					$tools[] = Linker::linkKnown( # Block link
						SpecialPage::getTitleFor( 'Block', $username ),
						$this->msg( 'blocklink' )->escaped()
					);
				}
			}

			# Block log link
			$tools[] = Linker::linkKnown(
				SpecialPage::getTitleFor( 'Log', 'block' ),
				$this->msg( 'sp-contributions-blocklog' )->escaped(),
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -298,7 +298,7 @@
 
 		if ( ( $id !== null ) || ( $id === null && IP::isIPAddress( $username ) ) ) {
 			if ( $this->getUser()->isAllowed( 'block' ) ) { # Block / Change block / Unblock links
-				if ( $target->isBlocked() ) {
+				if ( $target->isBlocked() && $target->getBlock()->getType() != Block::TYPE_AUTO ) {
 					$tools[] = Linker::linkKnown( # Change block link
 						SpecialPage::getTitleFor( 'Block', $username ),
 						$this->msg( 'change-blocklink' )->escaped()
```
