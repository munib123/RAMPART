# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1340_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1340_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 21-61 of the vulnerable file.

	public function test_target_as_first_attribute() {
		$content  = '<p>Links: <a target="_blank" href="#">No rel</a></p>';
		$expected = '<p>Links: <a target="_blank" href="#" rel="noopener noreferrer">No rel</a></p>';
		$this->assertEquals( $expected, wp_targeted_link_rel( $content ) );
	}

	public function test_add_to_existing_rel() {
		$content  = '<p>Links: <a href="/" rel="existing values" target="_blank">Existing rel</a></p>';
		$expected = '<p>Links: <a href="/" rel="existing values noopener noreferrer" target="_blank">Existing rel</a></p>';
		$this->assertEquals( $expected, wp_targeted_link_rel( $content ) );
	}

	public function test_no_duplicate_values_added() {
		$content  = '<p>Links: <a href="/" rel="existing noopener values" target="_blank">Existing rel</a></p>';
		$expected = '<p>Links: <a href="/" rel="existing noopener values noreferrer" target="_blank">Existing rel</a></p>';
		$this->assertEquals( $expected, wp_targeted_link_rel( $content ) );
	}

	public function test_rel_with_single_quote_delimiter() {
		$content  = '<p>Links: <a href="/" rel=\'existing values\' target="_blank">Existing rel</a></p>';
		$expected = '<p>Links: <a href="/" rel=\'existing values noopener noreferrer\' target="_blank">Existing rel</a></p>';
		$this->assertEquals( $expected, wp_targeted_link_rel( $content ) );
	}

	public function test_rel_with_no_delimiter() {
		$content  = '<p>Links: <a href="/" rel=existing target="_blank">Existing rel</a></p>';
		$expected = '<p>Links: <a href="/" rel="existing noopener noreferrer" target="_blank">Existing rel</a></p>';
		$this->assertEquals( $expected, wp_targeted_link_rel( $content ) );
	}

	public function test_rel_value_spaced_and_no_delimiter() {
		$content  = '<p>Links: <a href="/" rel = existing target="_blank">Existing rel</a></p>';
		$expected = '<p>Links: <a href="/" rel="existing noopener noreferrer" target="_blank">Existing rel</a></p>';
		$this->assertEquals( $expected, wp_targeted_link_rel( $content ) );
	}

	public function test_rel_value_spaced_and_no_delimiter_and_values_to_escape() {
		$content  = '<p>Links: <a href="/" rel = existing"value target="_blank">Existing rel</a></p>';
		$expected = '<p>Links: <a href="/" rel="existing&quot;value noopener noreferrer" target="_blank">Existing rel</a></p>';
		$this->assertEquals( $expected, wp_targeted_link_rel( $content ) );
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -38,7 +38,7 @@
 
 	public function test_rel_with_single_quote_delimiter() {
 		$content  = '<p>Links: <a href="/" rel=\'existing values\' target="_blank">Existing rel</a></p>';
-		$expected = '<p>Links: <a href="/" rel=\'existing values noopener noreferrer\' target="_blank">Existing rel</a></p>';
+		$expected = '<p>Links: <a href="/" rel="existing values noopener noreferrer" target="_blank">Existing rel</a></p>';
 		$this->assertEquals( $expected, wp_targeted_link_rel( $content ) );
 	}
 
@@ -51,12 +51,6 @@
 	public function test_rel_value_spaced_and_no_delimiter() {
 		$content  = '<p>Links: <a href="/" rel = existing target="_blank">Existing rel</a></p>';
 		$expected = '<p>Links: <a href="/" rel="existing noopener noreferrer" target="_blank">Existing rel</a></p>';
-		$this->assertEquals( $expected, wp_targeted_link_rel( $content ) );
-	}
-
-	public function test_rel_value_spaced_and_no_delimiter_and_values_to_escape() {
-		$content  = '<p>Links: <a href="/" rel = existing"value target="_blank">Existing rel</a></p>';
-		$expected = '<p>Links: <a href="/" rel="existing&quot;value noopener noreferrer" target="_blank">Existing rel</a></p>';
 		$this->assertEquals( $expected, wp_targeted_link_rel( $content ) );
 	}
 
@@ -114,17 +108,13 @@
 	}
 
 	/**
-	 * Ensure correct quotes are used when relation attribute (rel) is missing.
+	 * Ensure the content of style and script tags are not processed
 	 *
 	 * @ticket 47244
 	 */
-	public function test_wp_targeted_link_rel_should_use_correct_quotes() {
-		$content  = '<p>Links: <a href=\'\/\' target=\'_blank\'>No rel<\/a><\/p>';
-		$expected = '<p>Links: <a href=\'\/\' target=\'_blank\' rel=\'noopener noreferrer\'>No rel<\/a><\/p>';
-		$this->assertEquals( $expected, wp_targeted_link_rel( $content ) );
-
-		$content  = '<p>Links: <a href=\'\/\' target=_blank>No rel<\/a><\/p>';
-		$expected = '<p>Links: <a href=\'\/\' target=_blank rel=\'noopener noreferrer\'>No rel<\/a><\/p>';
+	public function test_wp_targeted_link_rel_skips_style_and_scripts() {
+		$content  = '<style><a href="/" target=a></style><p>Links: <script>console.log("<a href=\'/\' target=a>hi</a>");</script><script>alert(1);</script>here <a href="/" target=_blank>aq</a></p><script>console.log("<a href=\'last\' target=\'_blank\'")</script>';
+		$expected = '<style><a href="/" target=a></style><p>Links: <script>console.log("<a href=\'/\' target=a>hi</a>");</script><script>alert(1);</script>here <a href="/" target="_blank" rel="noopener noreferrer">aq</a></p><script>console.log("<a href=\'last\' target=\'_blank\'")</script>';
 		$this->assertEquals( $expected, wp_targeted_link_rel( $content ) );
 	}
 
@@ -139,4 +129,10 @@
 		$this->assertEquals( $expected, wp_targeted_link_rel( $content ) );
 	}
 
+	public function test_wp_targeted_link_rel_tab_separated_values_are_split() {
+		$content  = "<p>Links: <a href=\"/\" target=\"_blank\" rel=\"ugc\t\tnoopener\t\">No rel</a></p>";
+		$expected = '<p>Links: <a href="/" target="_blank" rel="ugc noopener noreferrer">No rel</a></p>';
+		$this->assertEquals( $expected, wp_targeted_link_rel( $content ) );
+	}
+
 }
```
