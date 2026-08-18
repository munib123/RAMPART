# CrossVul Fix Pair: Improper Input Validation in php
**Pair ID:** 2277_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2277_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```php
Lines 85-128 of the vulnerable file.

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
			$bugData->update( true, true );
		}
		echo " Done\n";
	}

	/**
	 * Compute and return the new link
 *
	 */
	private function getReplacementString( $oldLinkTag, $oldId ) {
		$linkTag = config_get( 'bug_link_tag' );

		$replacement = '';
		switch( $this->strategy_ ) {
			case 'link':
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -102,16 +102,27 @@
 
 		echo " Done\n";
 
-		$importedIssues = $this->itemsMap_->getall( 'issue' );
-		printf( "Processing cross-references for %s issues...", count( $importedIssues ) );
-		foreach( $importedIssues as $oldId => $newId ) {
-			$bugData = bug_get( $newId, true );
+		# replace bug references
+		$t_imported_issues = $this->itemsMap_->getall( 'issue' );
+		printf( 'Processing cross-references for %s issues...', count( $t_imported_issues ) );
+		foreach( $t_imported_issues as $t_old_id => $t_new_id ) {
+			$t_bug = bug_get( $t_new_id, true );
+			$t_content_replaced = false;
+			$t_bug_link_regexp = '/(^|[^\w])(' . preg_quote( $this->source_->issuelink, '/' ) . ')(\d+)\b/';
 
-			$bugLinkRegexp = '/(^|[^\w])(' . preg_quote( $this->source_->issuelink, '/' ) . ')(\d+)\b/e';
-			$replacement = '"\\1" . $this->getReplacementString( "\\2", "\\3" )';
+			# replace links in description
+			preg_match_all( $t_bug_link_regexp, $t_bug->description, $t_matches );
+			if( is_array( $t_matches[3] ) && count( $t_matches[3] ) > 0 ) {
+				$t_content_replaced = true;
+				foreach ( $t_matches[3] as $t_old_id2 ) {
+					$t_bug->description = str_replace( $this->source_->issuelink . $t_old_id2, $this->getReplacementString( $this->source_->issuelink, $t_old_id2 ), $t_bug->description );
+				}
+			}
 
-			$bugData->description = preg_replace( $bugLinkRegexp, $replacement, $bugData->description );
-			$bugData->update( true, true );
+			if( $t_content_replaced ) {
+				# only update bug if necessary (otherwise last update date would be unnecessarily overwritten)
+				$t_bug->update( true );
+			}
 		}
 		echo " Done\n";
 	}
```
