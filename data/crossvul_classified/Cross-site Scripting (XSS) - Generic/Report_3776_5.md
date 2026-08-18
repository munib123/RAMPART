# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3776_5
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3776_5`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 125-147 of the vulnerable file.

		$textObj->setValue($testString2);
		
		$this->assertEquals(
			'This is <span class="highlight">some</span> <span class="highlight">test</span> text. <span class="highlight">test</span> <span class="highlight">test</span> what if you have...',
			$textObj->ContextSummary(50, $testKeywords2)
		);
		
		$textObj->setValue($testString3);
		
		// test that it does not highlight too much (eg every a)
		$this->assertEquals(
			'A dog ate a cat while looking at a Foobar',
			$textObj->ContextSummary(100, $testKeyword3)
		);
		
		// it should highlight 3 letters or more.
		$this->assertEquals(
			'A dog <span class="highlight">ate</span> a cat while looking at a Foobar',
			$textObj->ContextSummary(100, $testKeyword3a)
		);
		
	}	
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -142,6 +142,30 @@
 			'A dog <span class="highlight">ate</span> a cat while looking at a Foobar',
 			$textObj->ContextSummary(100, $testKeyword3a)
 		);
-		
 	}	
+
+	public function testRAW() {
+		$data = DBField::create('Text', 'This &amp; This');
+		$this->assertEquals($data->RAW(), 'This &amp; This');
+	}
+	
+	public function testXML() {
+		$data = DBField::create('Text', 'This & This');
+		$this->assertEquals($data->XML(), 'This &amp; This');
+	}
+
+	public function testHTML() {
+		$data = DBField::create('Text', 'This & This');
+		$this->assertEquals($data->HTML(), 'This &amp; This');
+	}
+
+	public function testJS() {
+		$data = DBField::create('Text', '"this is a test"');
+		$this->assertEquals($data->JS(), '\"this is a test\"');
+	}
+
+	public function testATT() {
+		$data = DBField::create('Text', '"this is a test"');
+		$this->assertEquals($data->ATT(), '&quot;this is a test&quot;');
+	}
 }
```
