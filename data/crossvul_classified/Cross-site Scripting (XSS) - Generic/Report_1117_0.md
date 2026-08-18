# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1117_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1117_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 57-97 of the vulnerable file.

	if ( ! is_string( $post ) ) {
		$wp_post = get_post( $post );
		if ( $wp_post instanceof WP_Post ) {
			$post = $wp_post->post_content;
		}
	}

	return false !== strpos( (string) $post, '<!-- wp:' );
}

/**
 * Determine whether a $post or a string contains a specific block type.
 *
 * This test optimizes for performance rather than strict accuracy, detecting
 * the block type exists but not validating its structure. For strict accuracy,
 * you should use the block parser on post content.
 *
 * @since 5.0.0
 * @see parse_blocks()
 *
 * @param string                  $block_type Full Block type to look for.
 * @param int|string|WP_Post|null $post Optional. Post content, post ID, or post object. Defaults to global $post.
 * @return bool Whether the post content contains the specified block.
 */
function has_block( $block_type, $post = null ) {
	if ( ! has_blocks( $post ) ) {
		return false;
	}

	if ( ! is_string( $post ) ) {
		$wp_post = get_post( $post );
		if ( $wp_post instanceof WP_Post ) {
			$post = $wp_post->post_content;
		}
	}

	return false !== strpos( $post, '<!-- wp:' . $block_type . ' ' );
}

/**
 * Returns an array of the names of all registered dynamic block types.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -74,11 +74,11 @@
  * @since 5.0.0
  * @see parse_blocks()
  *
- * @param string                  $block_type Full Block type to look for.
+ * @param string                  $block_name Full Block type to look for.
  * @param int|string|WP_Post|null $post Optional. Post content, post ID, or post object. Defaults to global $post.
  * @return bool Whether the post content contains the specified block.
  */
-function has_block( $block_type, $post = null ) {
+function has_block( $block_name, $post = null ) {
 	if ( ! has_blocks( $post ) ) {
 		return false;
 	}
@@ -90,7 +90,30 @@
 		}
 	}
 
-	return false !== strpos( $post, '<!-- wp:' . $block_type . ' ' );
+	/*
+	 * Normalize block name to include namespace, if provided as non-namespaced.
+	 * This matches behavior for WordPress 5.0.0 - 5.3.0 in matching blocks by
+	 * their serialized names.
+	 */
+	if ( false === strpos( $block_name, '/' ) ) {
+		$block_name = 'core/' . $block_name;
+	}
+
+	// Test for existence of block by its fully qualified name.
+	$has_block = false !== strpos( $post, '<!-- wp:' . $block_name . ' ' );
+
+	if ( ! $has_block ) {
+		/*
+		 * If the given block name would serialize to a different name, test for
+		 * existence by the serialized form.
+		 */
+		$serialized_block_name = strip_core_block_namespace( $block_name );
+		if ( $serialized_block_name !== $block_name ) {
+			$has_block = false !== strpos( $post, '<!-- wp:' . $serialized_block_name . ' ' );
+		}
+	}
+
+	return $has_block;
 }
 
 /**
@@ -111,6 +134,207 @@
 	}
 
 	return $dynamic_block_names;
+}
+
+/**
+ * Given an array of attributes, returns a string in the serialized attributes
+ * format prepared for post content.
+ *
+ * The serialized result is a JSON-encoded string, with unicode escape sequence
+ * substitution for characters which might otherwise interfere with embedding
+ * the result in an HTML comment.
+ *
+ * @since 5.3.1
+ *
+ * @param array $attributes Attributes object.
+ * @return string Serialized attributes.
+ */
+function serialize_block_attributes( $block_attributes ) {
+	$encoded_attributes = json_encode( $block_attributes );
+	$encoded_attributes = preg_replace( '/--/', '\\u002d\\u002d', $encoded_attributes );
+	$encoded_attributes = preg_replace( '/</', '\\u003c', $encoded_attributes );
+	$encoded_attributes = preg_replace( '/>/', '\\u003e', $encoded_attributes );
+	$encoded_attributes = preg_replace( '/&/', '\\u0026', $encoded_attributes );
+	// Regex: /\\"/
+	$encoded_attributes = preg_replace( '/\\\\"/', '\\u0022', $encoded_attributes );
+
+	return $encoded_attributes;
+}
+
+/**
+ * Returns the block name to use for serialization. This will remove the default
+ * "core/" namespace from a block name.
+ *
+ * @since 5.3.1
+ *
+ * @param string $block_name Original block name.
+ * @return string Block name to use for serialization.
+ */
+function strip_core_block_namespace( $block_name = null ) {
+	if ( is_string( $block_name ) && 0 === strpos( $block_name, 'core/' ) ) {
+		return substr( $block_name, 5 );
+	}
+
+	return $block_name;
+}
+
+/**
+ * Returns the content of a block, including comment delimiters.
+ *
+ * @since 5.3.1
+ *
+ * @param string $block_name Block name.
+ * @param array  $attributes Block attributes.
+ * @param string $content    Block save content.
+ * @return string Comment-delimited block content.
+ */
+function get_comment_delimited_block_content( $block_name = null, $block_attributes, $block_content ) {
+	if ( is_null( $block_name ) ) {
+		return $block_content;
+	}
+
+	$serialized_block_name = strip_core_block_namespace( $block_name );
+	$serialized_attributes = empty( $block_attributes ) ? '' : serialize_block_attributes( $block_attributes ) . ' ';
+
+	if ( empty( $block_content ) ) {
+		return sprintf( '<!-- wp:%s %s/-->', $serialized_block_name, $serialized_attributes );
+	}
+
+	return sprintf(
+		'<!-- wp:%s %s-->%s<!-- /wp:%s -->',
+		$serialized_block_name,
+		$serialized_attributes,
+		$block_content,
+		$serialized_block_name
+	);
+}
+
+/**
+ * Returns the content of a block, including comment delimiters, serializing all
+ * attributes from the given parsed block.
+ *
+ * This should be used when preparing a block to be saved to post content.
+ * Prefer `render_block` when preparing a block for display. Unlike
+ * `render_block`, this does not evaluate a block's `render_callback`, and will
+ * instead preserve the markup as parsed.
+ *
+ * @since 5.3.1
+ *
+ * @param WP_Block_Parser_Block $block A single parsed block object.
+ * @return string String of rendered HTML.
+ */
+function serialize_block( $block ) {
+	$block_content = '';
+
+	$index = 0;
+	foreach ( $block['innerContent'] as $chunk ) {
+		$block_content .= is_string( $chunk ) ? $chunk : serialize_block( $block['innerBlocks'][ $index++ ] );
+	}
+
+	if ( ! is_array( $block['attrs'] ) ) {
+		$block['attrs'] = array();
+	}
+
+	return get_comment_delimited_block_content(
+		$block['blockName'],
+		$block['attrs'],
+		$block_content
+	);
+}
+
+/**
+ * Returns a joined string of the aggregate serialization of the given parsed
+ * blocks.
+ *
+ * @since 5.3.1
+ *
+ * @param WP_Block_Parser_Block[] $blocks Parsed block objects.
+ * @return string String of rendered HTML.
+ */
+function serialize_blocks( $blocks ) {
+	return implode( '', array_map( 'serialize_block', $blocks ) );
+}
+
+/**
+ * Filters and sanitizes block content to remove non-allowable HTML from
+ * parsed block attribute values.
+ *
+ * @since 5.3.1
+ *
+ * @param string         $text              Text that may contain block content.
+ * @param array[]|string $allowed_html      An array of allowed HTML elements
+ *                                          and attributes, or a context name
+ *                                          such as 'post'.
+ * @param string[]       $allowed_protocols Array of allowed URL protocols.
+ * @return string The filtered and sanitized content result.
+ */
+function filter_block_content( $text, $allowed_html = 'post', $allowed_protocols = array() ) {
+	$result = '';
+
+	$blocks = parse_blocks( $text );
+	foreach ( $blocks as $block ) {
+		$block   = filter_block_kses( $block, $allowed_html, $allowed_protocols );
+		$result .= serialize_block( $block );
+	}
+
+	return $result;
+}
+
+/**
+ * Filters and sanitizes a parsed block to remove non-allowable HTML from block
+ * attribute values.
+ *
+ * @since 5.3.1
+ *
+ * @param WP_Block_Parser_Block $block             The parsed block object.
+ * @param array[]|string        $allowed_html      An array of allowed HTML
+ *                                                 elements and attributes, or a
+ *                                                 context name such as 'post'.
+ * @param string[]              $allowed_protocols Allowed URL protocols.
+ * @return array The filtered and sanitized block object result.
+ */
+function filter_block_kses( $block, $allowed_html, $allowed_protocols = array() ) {
+	$block['attrs'] = filter_block_kses_value( $block['attrs'], $allowed_html, $allowed_protocols );
+
+	if ( is_array( $block['innerBlocks'] ) ) {
+		foreach ( $block['innerBlocks'] as $i => $inner_block ) {
+			$block['innerBlocks'][ $i ] = filter_block_kses( $inner_block, $allowed_html, $allowed_protocols );
+		}
+	}
+
+	return $block;
+}
+
+/**
+ * Filters and sanitizes a parsed block attribute value to remove non-allowable
+ * HTML.
+ *
+ * @since 5.3.1
+ *
+ * @param mixed          $value             The attribute value to filter.
+ * @param array[]|string $allowed_html      An array of allowed HTML elements
+ *                                          and attributes, or a context name
+ *                                          such as 'post'.
+ * @param string[]       $allowed_protocols Array of allowed URL protocols.
+ * @return array The filtered and sanitized result.
+ */
+function filter_block_kses_value( $value, $allowed_html, $allowed_protocols = array() ) {
+	if ( is_array( $value ) ) {
... (diff truncated)
```
