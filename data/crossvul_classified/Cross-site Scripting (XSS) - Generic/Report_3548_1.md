# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3548_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3548_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 119-149 of the vulnerable file.

			
			
		$tmpl3 = SSViewer::fromString('<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
			<html>
				<head><% base_tag %></head>
				<body><p>test</p><body>
			</html>');
		$this->assertRegExp('/<head><base href=".*"><!--\[if lte IE 6\]><\/base><!\[endif\]--><\/head>/', $tmpl3->process(new ViewableData()));

		// Check that the content negotiator converts to the equally legal formats
		$negotiator = new ContentNegotiator();
		
		$response = new SS_HTTPResponse($tmpl1->process(new ViewableData()));
		$negotiator->html($response);
		$this->assertRegExp('/<head><base href=".*"><!--\[if lte IE 6\]><\/base><!\[endif\]--><\/head>/', $response->getBody());

		$response = new SS_HTTPResponse($tmpl1->process(new ViewableData()));
		$negotiator->xhtml($response);
		$this->assertRegExp('/<head><base href=".*" \/><\/head>/', $response->getBody());
	}
}

class SSViewerTest_ViewableData extends ViewableData implements TestOnly {
	function methodWithOneArgument($arg1) {
		return "arg1:{$arg1}";
	}
	
	function methodWithTwoArguments($arg1, $arg2) {
		return "arg1:{$arg1},arg2:{$arg2}";
	}
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -136,6 +136,76 @@
 		$negotiator->xhtml($response);
 		$this->assertRegExp('/<head><base href=".*" \/><\/head>/', $response->getBody());
 	}
+	
+	function testRewriteHashlinks() {
+		$oldRewriteHashLinks = SSViewer::getOption('rewriteHashlinks');
+		SSViewer::setOption('rewriteHashlinks', true);
+		
+		// Emulate SSViewer::process()
+		$base = Convert::raw2att($_SERVER['REQUEST_URI']);
+		
+		$tmplFile = TEMP_FOLDER . '/SSViewerTest_testRewriteHashlinks_' . sha1(rand()) . '.ss';
+		
+		// Note: SSViewer_FromString doesn't rewrite hash links.
+		file_put_contents($tmplFile, '<!DOCTYPE html>
+			<html>
+				<head><% base_tag %></head>
+				<body>
+				<a class="inline" href="#anchor">InlineLink</a>
+				$InsertedLink
+				<body>
+			</html>');
+		$tmpl = new SSViewer($tmplFile);
+		$obj = new ViewableData();
+		$obj->InsertedLink = '<a class="inserted" href="#anchor">InsertedLink</a>';
+		$result = $tmpl->process($obj);
+		$this->assertContains(
+			'<a class="inserted" href="' . $base . '#anchor">InsertedLink</a>',
+			$result
+		);
+		$this->assertContains(
+			'<a class="inline" href="' . $base . '#anchor">InlineLink</a>',
+			$result
+		);
+		
+		unlink($tmplFile);
+		
+		SSViewer::setOption('rewriteHashlinks', $oldRewriteHashLinks);
+	}
+	
+	function testRewriteHashlinksInPhpMode() {
+		$oldRewriteHashLinks = SSViewer::getOption('rewriteHashlinks');
+		SSViewer::setOption('rewriteHashlinks', 'php');
+		
+		$tmplFile = TEMP_FOLDER . '/SSViewerTest_testRewriteHashlinksInPhpMode_' . sha1(rand()) . '.ss';
+		
+		// Note: SSViewer_FromString doesn't rewrite hash links.
+		file_put_contents($tmplFile, '<!DOCTYPE html>
+			<html>
+				<head><% base_tag %></head>
+				<body>
+				<a class="inline" href="#anchor">InlineLink</a>
+				$InsertedLink
+				<body>
+			</html>');
+		$tmpl = new SSViewer($tmplFile);
+		$obj = new ViewableData();
+		$obj->InsertedLink = '<a class="inserted" href="#anchor">InsertedLink</a>';
+		$result = $tmpl->process($obj);
+		$this->assertContains(
+			'<a class="inserted" href="<?php echo str_replace(',
+			$result
+		);
+		// TODO Fix inline links in PHP mode
+		// $this->assertContains(
+		// 	'<a class="inline" href="<?php echo str_replace(',
+		// 	$result
+		// );
+		
+		unlink($tmplFile);
+		
+		SSViewer::setOption('rewriteHashlinks', $oldRewriteHashLinks);
+	}
 }
 
 class SSViewerTest_ViewableData extends ViewableData implements TestOnly {
```
