# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2119_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2119_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 245-285 of the vulnerable file.

		if ( $title->isRedirect() ) {
			$pageInfo['header-basic'][] = array(
				$this->msg( 'pageinfo-redirectsto' ),
				Linker::link( $this->page->getRedirectTarget() ) .
				$this->msg( 'word-separator' )->text() .
				$this->msg( 'parentheses', Linker::link(
					$this->page->getRedirectTarget(),
					$this->msg( 'pageinfo-redirectsto-info' )->escaped(),
					array(),
					array( 'action' => 'info' )
				) )->text()
			);
		}

		// Default sort key
		$sortKey = $title->getCategorySortkey();
		if ( !empty( $pageProperties['defaultsort'] ) ) {
			$sortKey = $pageProperties['defaultsort'];
		}

		$pageInfo['header-basic'][] = array( $this->msg( 'pageinfo-default-sort' ), $sortKey );

		// Page length (in bytes)
		$pageInfo['header-basic'][] = array(
			$this->msg( 'pageinfo-length' ), $lang->formatNum( $title->getLength() )
		);

		// Page ID (number not localised, as it's a database ID)
		$pageInfo['header-basic'][] = array( $this->msg( 'pageinfo-article-id' ), $id );

		// Language in which the page content is (supposed to be) written
		$pageLang = $title->getPageLanguage()->getCode();
		$pageInfo['header-basic'][] = array( $this->msg( 'pageinfo-language' ),
			Language::fetchLanguageName( $pageLang, $lang->getCode() )
			. ' ' . $this->msg( 'parentheses', $pageLang ) );

		// Content model of the page
		$pageInfo['header-basic'][] = array(
			$this->msg( 'pageinfo-content-model' ),
			ContentHandler::getLocalizedName( $title->getContentModel() )
		);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -262,6 +262,7 @@
 			$sortKey = $pageProperties['defaultsort'];
 		}
 
+		$sortKey = htmlspecialchars( $sortKey );
 		$pageInfo['header-basic'][] = array( $this->msg( 'pageinfo-default-sort' ), $sortKey );
 
 		// Page length (in bytes)
```
