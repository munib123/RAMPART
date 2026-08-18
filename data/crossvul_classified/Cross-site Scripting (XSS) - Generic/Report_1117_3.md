# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1117_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1117_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 287-327 of the vulnerable file.

	/**
	 * @ticket 45097
	 */
	public function test_post_has_block() {
		// should fail for a non-existent block `custom/fake`.
		$this->assertFalse( has_block( 'custom/fake', self::$post_with_blocks ) );

		// this functions should not work without the second param until the $post global is set.
		$this->assertFalse( has_block( 'core/text' ) );
		$this->assertFalse( has_block( 'core/fake' ) );

		global $post;
		$post = get_post( self::$post_with_blocks );

		// check if the function correctly detects content from the $post global.
		$this->assertTrue( has_block( 'core/text' ) );
		// even if it detects a proper $post global it should still be false for a missing block.
		$this->assertFalse( has_block( 'core/fake' ) );
	}

	/**
	 * Renders a test block without content.
	 *
	 * @since 5.0.0
	 *
	 * @param array $attributes Block attributes. Default empty array.
	 * @return string JSON encoded list of attributes.
	 */
	public function render_fake_block( $attributes ) {
		return json_encode( $attributes );
	}

	/**
	 * Renders a test block with content.
	 *
	 * @since 5.0.0
	 *
	 * @param array  $attributes Block attributes. Default empty array.
	 * @param string $content    Block content. Default empty string.
	 * @return string JSON encoded list of attributes.
	 */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -302,6 +302,24 @@
 		$this->assertTrue( has_block( 'core/text' ) );
 		// even if it detects a proper $post global it should still be false for a missing block.
 		$this->assertFalse( has_block( 'core/fake' ) );
+	}
+
+	public function test_post_has_block_serialized_name() {
+		$content = '<!-- wp:serialized /--><!-- wp:core/normalized /--><!-- wp:plugin/third-party /-->';
+
+		$this->assertTrue( has_block( 'core/serialized', $content ) );
+
+		/*
+		 * Technically, `has_block` should receive a "full" (normalized, parsed)
+		 * block name. But this test conforms to expected pre-5.3.1 behavior.
+		 */
+		$this->assertTrue( has_block( 'serialized', $content ) );
+		$this->assertTrue( has_block( 'core/normalized', $content ) );
+		$this->assertTrue( has_block( 'normalized', $content ) );
+		$this->assertFalse( has_block( 'plugin/normalized', $content ) );
+		$this->assertFalse( has_block( 'plugin/serialized', $content ) );
+		$this->assertFalse( has_block( 'third-party', $content ) );
+		$this->assertFalse( has_block( 'core/third-party', $content ) );
 	}
 
 	/**
```
