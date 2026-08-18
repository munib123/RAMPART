# CrossVul Fix Pair: Improper Input Validation in php
**Pair ID:** 4035_2
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4035_2`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```php
Lines 129-169 of the vulnerable file.

				case "#test .help":
					$this->assertSame(110, $oSelector->getSpecificity());
					break;
				case "#file":
					$this->assertSame(100, $oSelector->getSpecificity());
					break;
				case ".help:hover":
					$this->assertSame(20, $oSelector->getSpecificity());
					break;
				case "ol li::before":
					$this->assertSame(3, $oSelector->getSpecificity());
					break;
				case "li.green":
					$this->assertSame(11, $oSelector->getSpecificity());
					break;
				default:
					$this->fail("specificity: untested selector " . $oSelector->getSelector());
			}
		}
		$this->assertEquals(array(new Selector('#test .help', true)), $oDoc->getSelectorsBySpecificity('> 100'));
	}

	function testManipulation() {
		$oDoc = $this->parsedStructureForFile('atrules');
		$this->assertSame('@charset "utf-8";@font-face {font-family: "CrassRoots";src: url("../media/cr.ttf");}html, body {font-size: 1.6em;}
@keyframes mymove {from {top: 0px;}
to {top: 200px;}
}@-moz-keyframes some-move {from {top: 0px;}
to {top: 200px;}
}', $oDoc->__toString());
		foreach ($oDoc->getAllDeclarationBlocks() as $oBlock) {
			foreach ($oBlock->getSelectors() as $oSelector) {
				//Loop over all selector parts (the comma-separated strings in a selector) and prepend the id
				$oSelector->setSelector('#my_id ' . $oSelector->getSelector());
			}
		}
		$this->assertSame('@charset "utf-8";@font-face {font-family: "CrassRoots";src: url("../media/cr.ttf");}#my_id html, #my_id body {font-size: 1.6em;}
@keyframes mymove {from {top: 0px;}
to {top: 200px;}
}@-moz-keyframes some-move {from {top: 0px;}
to {top: 200px;}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -146,6 +146,13 @@
 			}
 		}
 		$this->assertEquals(array(new Selector('#test .help', true)), $oDoc->getSelectorsBySpecificity('> 100'));
+		$this->assertEquals(array(new Selector('#test .help', true), new Selector('#file', true)), $oDoc->getSelectorsBySpecificity('>= 100'));
+		$this->assertEquals(array(new Selector('#file', true)), $oDoc->getSelectorsBySpecificity('=== 100'));
+		$this->assertEquals(array(new Selector('#file', true)), $oDoc->getSelectorsBySpecificity('== 100'));
+		$this->assertEquals(array(new Selector('#file', true), new Selector('.help:hover', true), new Selector('li.green', true), new Selector('ol li::before', true)), $oDoc->getSelectorsBySpecificity('<= 100'));
+		$this->assertEquals(array(new Selector('.help:hover', true), new Selector('li.green', true), new Selector('ol li::before', true)), $oDoc->getSelectorsBySpecificity('< 100'));
+		$this->assertEquals(array(new Selector('li.green', true)), $oDoc->getSelectorsBySpecificity('11'));
+		$this->assertEquals(array(new Selector('ol li::before', true)), $oDoc->getSelectorsBySpecificity(3));
 	}
 
 	function testManipulation() {
```
