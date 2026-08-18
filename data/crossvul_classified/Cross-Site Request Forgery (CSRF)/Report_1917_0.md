# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 1917_0
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1917_0`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 38-78 of the vulnerable file.

		if (!$rev) {
			$out->addHTML(Html::rawElement(
				'p',
				[ 'class' => 'error' ],
				wfMessage( 'report-error-invalid-revid', $par )->escaped()
			));
			return;
		}
		$dbr = wfGetDB( DB_REPLICA );
		if ($dbr->selectRow( 'report_reports', [ 'report_id' ], [
			'report_revid' => $rev->getId(),
			'report_user' => $user->getId()
		], __METHOD__ )) {
			$out->addHTML(Html::rawElement( 'p', [],
				wfMessage( 'report-already-reported' )->escaped()
			));
			return;
		}
		$request = $this->getRequest();
		if ($request->wasPosted()) {
			return self::onPost( $par, $out, $request );
		}
		$out->setIndexPolicy( 'noindex' );
		$out->addHTML(
			Html::rawElement(
				'p',
				[ 'class' => 'mw-report-intro' ],
				wfMessage( 'report-intro' )
					->params( $par )
					->parse()
			)
		);
		$out->addHTML(Html::openElement(
				'form',
				[ 'method' => 'POST' ]
		));
		$out->addHTML(Html::rawElement(
			'input',
			[
				'type' => 'hidden',
				'name' => 'revid',
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -55,7 +55,7 @@
 		}
 		$request = $this->getRequest();
 		if ($request->wasPosted()) {
-			return self::onPost( $par, $out, $request );
+			return self::onPost( $par, $out, $request, $user );
 		}
 		$out->setIndexPolicy( 'noindex' );
 		$out->addHTML(
@@ -90,6 +90,14 @@
 		$out->addHTML(Html::rawElement(
 			'input',
 			[
+				'type' => 'hidden',
+				'name' => 'token',
+				'value' => $user->getEditToken()
+			]
+		));
+		$out->addHTML(Html::rawElement(
+			'input',
+			[
 				'type' => 'submit',
 				'id' => 'mw-report-form-submit',
 				'value' => wfMessage( 'report-submit' )
@@ -98,29 +106,31 @@
 		$out->addHTML(Html::closeElement( 'form' ));
 	}
 
-	static public function onPost( $par, $out, $request ) {
-		global $wgUser;
+	static public function onPost( $par, $out, $request, $user ) {
+		if (!$user->matchEditToken($request->getText( 'token' ))) {
+			$out->addWikiMsg( 'sessionfailure' );
+			return;
+		}
 		if (!$request->getText('reason')) {
 			$out->addHTML(Html::rawElement(
 				'p',
 				[ 'class' => 'error '],
 				wfMessage( 'report-error-missing-reason' )->escaped()
 			));
-		} else {
-			$dbw = wfGetDB( DB_MASTER );
-			$dbw->startAtomic(__METHOD__);
-			$dbw->insert( 'report_reports', [
-				'report_revid' => (int)$par,
-				'report_reason' => $request->getText('reason'),
-				'report_user' => $wgUser->getId(),
-				'report_user_text' => $wgUser->getName(),
-				'report_timestamp' => wfTimestampNow()
-			], __METHOD__ );
-			$dbw->endAtomic(__METHOD__);
-			$out->addWikiMsg( 'report-success' );
-			$out->addWikiMsg( 'returnto', '[[' . SpecialPage::getTitleFor('Diff', $par)->getPrefixedText() . ']]' );
 			return;
 		}
+		$dbw = wfGetDB( DB_MASTER );
+		$dbw->startAtomic(__METHOD__);
+		$dbw->insert( 'report_reports', [
+			'report_revid' => (int)$par,
+			'report_reason' => $request->getText('reason'),
+			'report_user' => $user->getId(),
+			'report_user_text' => $user->getName(),
+			'report_timestamp' => wfTimestampNow()
+		], __METHOD__ );
+		$dbw->endAtomic(__METHOD__);
+		$out->addWikiMsg( 'report-success' );
+		$out->addWikiMsg( 'returnto', '[[' . SpecialPage::getTitleFor('Diff', $par)->getPrefixedText() . ']]' );
 	}
 
 	public function getGroupName() {
```
