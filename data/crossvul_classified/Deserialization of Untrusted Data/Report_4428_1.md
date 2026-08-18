# CrossVul Fix Pair: Deserialization of Untrusted Data in php
**Pair ID:** 4428_1
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4428_1`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```php
Lines 250-290 of the vulnerable file.

	function test_maybe_unserialize( $value, $is_serialized ) {
		if ( $is_serialized ) {
			$expected = unserialize( trim( $value ) );
		} else {
			$expected = $value;
		}

		if ( is_object( $expected ) ) {
			$this->assertEquals( $expected, maybe_unserialize( $value ) );
		} else {
			$this->assertSame( $expected, maybe_unserialize( $value ) );
		}
	}

	/**
	 * @dataProvider data_is_serialized
	 * @dataProvider data_is_not_serialized
	 */
	function test_is_serialized( $value, $expected ) {
		$this->assertSame( $expected, is_serialized( $value ) );
	}

	function data_is_serialized() {
		return array(
			array( serialize( null ), true ),
			array( serialize( true ), true ),
			array( serialize( false ), true ),
			array( serialize( -25 ), true ),
			array( serialize( 25 ), true ),
			array( serialize( 1.1 ), true ),
			array( serialize( 'this string will be serialized' ), true ),
			array( serialize( "a\nb" ), true ),
			array( serialize( array() ), true ),
			array( serialize( array( 1, 1, 2, 3, 5, 8, 13 ) ), true ),
			array(
				serialize(
					(object) array(
						'test' => true,
						'3',
						4,
					)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -267,6 +267,35 @@
 	 */
 	function test_is_serialized( $value, $expected ) {
 		$this->assertSame( $expected, is_serialized( $value ) );
+	}
+
+	/**
+	 * @dataProvider data_serialize_deserialize_objects
+	 */
+	function test_deserialize_request_utility_filtered_iterator_objects( $value ) {
+		$serialized = maybe_serialize( $value );
+		if ( get_class( $value ) === 'Requests_Utility_FilteredIterator' ) {
+			$new_value = unserialize( $serialized );
+			if ( version_compare( PHP_VERSION, '5.3', '>=' ) ) {
+				$property = ( new ReflectionClass( 'Requests_Utility_FilteredIterator' ) )->getProperty( 'callback' );
+				$property->setAccessible( true );
+				$callback_value = $property->getValue( $new_value );
+				$this->assertSame( null, $callback_value );
+			} else {
+				$current_item = @$new_value->current(); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
+				$this->assertSame( null, $current_item );
+			}
+		} else {
+			$this->assertEquals( $value->count(), unserialize( $serialized )->count() );
+		}
+	}
+
+	function data_serialize_deserialize_objects() {
+		return array(
+			array( new Requests_Utility_FilteredIterator( array( 1 ), 'md5' ) ),
+			array( new Requests_Utility_FilteredIterator( array( 1, 2 ), 'sha1' ) ),
+			array( new ArrayIterator( array( 1, 2, 3 ) ) ),
+		);
 	}
 
 	function data_is_serialized() {
```
