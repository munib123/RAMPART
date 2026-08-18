# CrossVul Fix Pair: Improper Input Validation in php
**Pair ID:** 1339_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1339_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```php
Lines 159-199 of the vulnerable file.

						$this->assertEquals( str_replace( '&', '&amp;', $x ), $result );
						break;
					case 22:
						$this->assertEquals( 'javascript&amp;#0000058alert(1);', $result );
						break;
					case 23:
						$this->assertEquals( 'javascript&amp;#0000058alert(1)//?:', $result );
						break;
					case 24:
						$this->assertEquals( 'feed:alert(1)', $result );
						break;
					case 26:
						$this->assertEquals( 'javascript&amp;#58alert(1)', $result );
						break;
					case 27:
						$this->assertEquals( 'javascript&amp;#x3ax=1;alert(1)', $result );
						break;
					default:
						$this->fail( "wp_kses_bad_protocol failed on $k, $x. Result: $result" );
				}
			}
		}

		$safe = array(
			'dummy:alert(1)',
			'HTTP://example.org/',
			'http://example.org/',
			'http&#58;//example.org/',
			'http&#x3A;//example.org/',
			'https://example.org',
			'http://example.org/wp-admin/post.php?post=2&amp;action=edit',
			'http://example.org/index.php?test=&#039;blah&#039;',
		);
		foreach ( $safe as $x ) {
			$result = wp_kses_bad_protocol( wp_kses_normalize_entities( $x ), array( 'http', 'https', 'dummy' ) );
			if ( $result !== $x && 'http://example.org/' !== $result ) {
				$this->fail( "wp_kses_bad_protocol incorrectly blocked $x" );
			}
		}
	}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -179,6 +179,28 @@
 			}
 		}
 
+		$bad_not_normalized = array(
+			'dummy&colon;alert(1)',
+			'javascript&colon;alert(1)',
+			'javascript&CoLon;alert(1)',
+			'javascript&COLON;alert(1);',
+			'javascript&#58;alert(1);',
+			'javascript&#0058;alert(1);',
+			'javascript&#0000058alert(1);',
+			'jav	ascript&COLON;alert(1);',
+			'javascript&#58;javascript&colon;alert(1);',
+			'javascript&#58;javascript&colon;alert(1);',
+			'javascript&#0000058javascript&colon;alert(1);',
+			'javascript&#58;javascript&#0000058alert(1);',
+			'javascript&#58alert(1)',
+		);
+		foreach ( $bad_not_normalized as $k => $x ) {
+			$result = wp_kses_bad_protocol( $x, wp_allowed_protocols() );
+			if ( ! empty( $result ) && 'alert(1);' !== $result && 'alert(1)' !== $result ) {
+				$this->fail( "wp_kses_bad_protocol failed on $k, $x. Result: $result" );
+			}
+		}
+
 		$safe = array(
 			'dummy:alert(1)',
 			'HTTP://example.org/',
```
