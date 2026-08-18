# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3776_4
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3776_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 85-106 of the vulnerable file.

			$textObj = new HTMLText();
			$textObj->setValue($orig);
			$this->assertEquals($match, $textObj->Summary(4, 0, ''));
		}
	}

	function testFirstSentence() {
		$many = str_repeat('many ', 100);
		$cases = array(
			'<h1>should ignore</h1><p>First sentence. Second sentence.</p>' => 'First sentence.',
			'<h1>should ignore</h1><p>First Mr. sentence. Second sentence.</p>' => 'First Mr. sentence.',
			"<h1>should ignore</h1><p>Sentence with {$many}words. Second sentence.</p>" => "Sentence with {$many}words.",
		);
		
		foreach($cases as $orig => $match) {
			$textObj = new HTMLText();
			$textObj->setValue($orig);
			$this->assertEquals($match, $textObj->FirstSentence());
		}
	}	
}
?>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -102,5 +102,33 @@
 			$this->assertEquals($match, $textObj->FirstSentence());
 		}
 	}	
+
+	public function testRAW() {
+		$data = DBField::create('HTMLText', 'This &amp; This');
+		$this->assertEquals($data->RAW(), 'This &amp; This');
+
+		$data = DBField::create('HTMLText', 'This & This');
+		$this->assertEquals($data->RAW(), 'This & This');
+	}
+	
+	public function testXML() {
+		$data = DBField::create('HTMLText', 'This & This');
+		$this->assertEquals($data->XML(), 'This &amp; This');
+	}
+
+	public function testHTML() {
+		$data = DBField::create('HTMLText', 'This & This');
+		$this->assertEquals($data->HTML(), 'This &amp; This');
+	}
+
+	public function testJS() {
+		$data = DBField::create('HTMLText', '"this is a test"');
+		$this->assertEquals($data->JS(), '\"this is a test\"');
+	}
+
+	public function testATT() {
+		$data = DBField::create('HTMLText', '"this is a test"');
+		$this->assertEquals($data->ATT(), '&quot;this is a test&quot;');
+	}
 }
 ?>
```
