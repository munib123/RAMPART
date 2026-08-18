# CrossVul Fix Pair: Deserialization of Untrusted Data in php
**Pair ID:** 4428_0
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4428_0`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```php
Lines 25-45 of the vulnerable file.

	 *
	 * @param array $data
	 * @param callable $callback Callback to be called on each value
	 */
	public function __construct($data, $callback) {
		parent::__construct($data);

		$this->callback = $callback;
	}

	/**
	 * Get the current item's value after filtering
	 *
	 * @return string
	 */
	public function current() {
		$value = parent::current();
		$value = call_user_func($this->callback, $value);
		return $value;
	}
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -42,4 +42,20 @@
 		$value = call_user_func($this->callback, $value);
 		return $value;
 	}
+
+	/**
+	 * @inheritdoc
+	 */
+	public function unserialize( $serialized ) {
+	}
+
+	/**
+	 * @inheritdoc
+	 */
+	public function __unserialize( $serialized ) { // phpcs:ignore PHPCompatibility.FunctionNameRestrictions.ReservedFunctionNames.MethodDoubleUnderscore,PHPCompatibility.FunctionNameRestrictions.NewMagicMethods.__unserializeFound
+	}
+
+	public function __wakeup() { // phpcs:ignore PHPCompatibility.FunctionNameRestrictions.ReservedFunctionNames.MethodDoubleUnderscore,PHPCompatibility.FunctionNameRestrictions.NewMagicMethods.__wakeupFound
+		unset( $this->callback );
+	}
 }
```
