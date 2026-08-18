# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 82_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `82_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 4232-4272 of the vulnerable file.

			case 'commentsrss2_head':
				$type = 'rss2';
				break;
			case 'rss_head':
			case 'opml_head':
				$type = 'comment';
				break;
			case 'rdf_header':
				$type = 'rdf';
				break;
			case 'atom_head':
			case 'comments_atom_head':
			case 'app_head':
				$type = 'atom';
				break;
		}
	}

	switch ( $type ) {
		case 'html':
			$gen = '<meta name="generator" content="WordPress ' . get_bloginfo( 'version' ) . '">';
			break;
		case 'xhtml':
			$gen = '<meta name="generator" content="WordPress ' . get_bloginfo( 'version' ) . '" />';
			break;
		case 'atom':
			$gen = '<generator uri="https://wordpress.org/" version="' . get_bloginfo_rss( 'version' ) . '">WordPress</generator>';
			break;
		case 'rss2':
			$gen = '<generator>https://wordpress.org/?v=' . get_bloginfo_rss( 'version' ) . '</generator>';
			break;
		case 'rdf':
			$gen = '<admin:generatorAgent rdf:resource="https://wordpress.org/?v=' . get_bloginfo_rss( 'version' ) . '" />';
			break;
		case 'comment':
			$gen = '<!-- generator="WordPress/' . get_bloginfo( 'version' ) . '" -->';
			break;
		case 'export':
			$gen = '<!-- generator="WordPress/' . get_bloginfo_rss( 'version' ) . '" created="' . date( 'Y-m-d H:i' ) . '" -->';
			break;
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4249,25 +4249,25 @@
 
 	switch ( $type ) {
 		case 'html':
-			$gen = '<meta name="generator" content="WordPress ' . get_bloginfo( 'version' ) . '">';
+			$gen = '<meta name="generator" content="WordPress ' . esc_attr( get_bloginfo( 'version' ) ) . '">';
 			break;
 		case 'xhtml':
-			$gen = '<meta name="generator" content="WordPress ' . get_bloginfo( 'version' ) . '" />';
+			$gen = '<meta name="generator" content="WordPress ' . esc_attr( get_bloginfo( 'version' ) ) . '" />';
 			break;
 		case 'atom':
-			$gen = '<generator uri="https://wordpress.org/" version="' . get_bloginfo_rss( 'version' ) . '">WordPress</generator>';
+			$gen = '<generator uri="https://wordpress.org/" version="' . esc_attr( get_bloginfo_rss( 'version' ) ) . '">WordPress</generator>';
 			break;
 		case 'rss2':
-			$gen = '<generator>https://wordpress.org/?v=' . get_bloginfo_rss( 'version' ) . '</generator>';
+			$gen = '<generator>' . esc_url_raw( 'https://wordpress.org/?v=' . get_bloginfo_rss( 'version' ) ) . '</generator>';
 			break;
 		case 'rdf':
-			$gen = '<admin:generatorAgent rdf:resource="https://wordpress.org/?v=' . get_bloginfo_rss( 'version' ) . '" />';
+			$gen = '<admin:generatorAgent rdf:resource="' . esc_url_raw( 'https://wordpress.org/?v=' . get_bloginfo_rss( 'version' ) ) . '" />';
 			break;
 		case 'comment':
-			$gen = '<!-- generator="WordPress/' . get_bloginfo( 'version' ) . '" -->';
+			$gen = '<!-- generator="WordPress/' . esc_attr( get_bloginfo( 'version' ) ) . '" -->';
 			break;
 		case 'export':
-			$gen = '<!-- generator="WordPress/' . get_bloginfo_rss( 'version' ) . '" created="' . date( 'Y-m-d H:i' ) . '" -->';
+			$gen = '<!-- generator="WordPress/' . esc_attr( get_bloginfo_rss( 'version' ) ) . '" created="' . date( 'Y-m-d H:i' ) . '" -->';
 			break;
 	}
 
```
