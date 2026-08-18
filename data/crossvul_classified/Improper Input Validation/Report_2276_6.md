# CrossVul Fix Pair: Improper Input Validation in php
**Pair ID:** 2276_6
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2276_6`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```php
Lines 85-125 of the vulnerable file.

		echo 'Importing file, please wait...';

		// loop through the elements
		while( $this->reader_->read( ) ) {
			switch( $this->reader_->nodeType ) {
				case XMLReader::ELEMENT:

					/* element start */
					$t_element_name = $this->reader_->localName;
					$t_importer = $this->get_importer_object( $t_element_name );
					if( !is_null( $t_importer ) ) {
						$t_importer->process( $this->reader_ );
						$t_importer->update_map( $this->itemsMap_ );
					}
					break;
			}
		}

		echo " Done\n";

		$importedIssues = $this->itemsMap_->getall( 'issue' );
		printf( "Processing cross-references for %s issues...", count( $importedIssues ) );
		foreach( $importedIssues as $oldId => $newId ) {
			$bugData = bug_get( $newId, true );

			$bugLinkRegexp = '/(^|[^\w])(' . preg_quote( $this->source_->issuelink, '/' ) . ')(\d+)\b/e';
			$replacement = '"\\1" . $this->getReplacementString( "\\2", "\\3" )';

			$bugData->description = preg_replace( $bugLinkRegexp, $replacement, $bugData->description );
			bug_update( $newId, $bugData, true, true );
		}
		echo " Done\n";
	}

	/**
	 * Compute and return the new link
 *
	 */
	private function getReplacementString( $oldLinkTag, $oldId ) {
		$linkTag = config_get( 'bug_link_tag' );

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -102,23 +102,42 @@
 
 		echo " Done\n";
 
+		// replace references in bug description and additional information
 		$importedIssues = $this->itemsMap_->getall( 'issue' );
 		printf( "Processing cross-references for %s issues...", count( $importedIssues ) );
 		foreach( $importedIssues as $oldId => $newId ) {
 			$bugData = bug_get( $newId, true );
 
 			$bugLinkRegexp = '/(^|[^\w])(' . preg_quote( $this->source_->issuelink, '/' ) . ')(\d+)\b/e';
-			$replacement = '"\\1" . $this->getReplacementString( "\\2", "\\3" )';
-
-			$bugData->description = preg_replace( $bugLinkRegexp, $replacement, $bugData->description );
-			bug_update( $newId, $bugData, true, true );
-		}
+			// replace links in description
+			preg_match_all( $bugLinkRegexp, $bugData->description, $matches );
+			if ( is_array( $matches[3] && count( $matches[3] ) > 0 ) ) {
+				$content_replaced = true;
+				foreach ( $matches[3] as $old_id ) {
+					$bugData->description = str_replace( $this->source_->issuelink . $old_id, $this->getReplacementString( $this->source_->issuelink, $old_id ), $bugData->description);
+				}
+			}
+			// replace links in additional information
+			preg_match_all( $bugLinkRegexp, $bugData->additional_information, $matches );
+			if ( is_array( $matches[3] && count( $matches[3] ) > 0 ) ) {
+				$content_replaced = true;
+				foreach ( $matches[3] as $old_id ) {
+					$bugData->additional_information = str_replace( $this->source_->issuelink . $old_id, $this->getReplacementString( $this->source_->issuelink, $old_id ), $bugData->additional_information);
+				}
+			}
+			if ( $content_replaced ) {
+				// only update bug if necessary (otherwise last update date would be unnecessarily overwritten)
+				$bugData->update( true );
+			}
+		}
+
+		// @todo: replace references within bugnotes
 		echo " Done\n";
 	}
 
 	/**
 	 * Compute and return the new link
- *
+	 *
 	 */
 	private function getReplacementString( $oldLinkTag, $oldId ) {
 		$linkTag = config_get( 'bug_link_tag' );
```
