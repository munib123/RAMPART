# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3606_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3606_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 55-77 of the vulnerable file.

			$chunks = explode('?', $this->getParameter('querystring'));

			// get extension
			$extension = SpoonFile::getExtension($chunks[0]);

			// if the file has an extension it is a non-existing-file
			if($extension != '' && $extension != $chunks[0])
			{
				// set correct headers
				SpoonHTTP::setHeadersByCode(404);

				// give a nice error, so we can detect which file is missing
				echo 'Requested file (' . implode('?', $chunks) . ') not found.';

				// stop script execution
				exit;
			}
		}

		// assign the correct message into the template
		$this->tpl->assign('message', BL::err(SpoonFilter::toCamelCase($errorType, '-')));
	}
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -72,6 +72,6 @@
 		}
 
 		// assign the correct message into the template
-		$this->tpl->assign('message', BL::err(SpoonFilter::toCamelCase($errorType, '-')));
+		$this->tpl->assign('message', BL::err(SpoonFilter::toCamelCase(htmlspecialchars($errorType), '-')));
 	}
 }
```
