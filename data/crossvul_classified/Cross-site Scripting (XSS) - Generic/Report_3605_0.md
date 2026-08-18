# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3605_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3605_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 47-77 of the vulnerable file.

				SpoonHTTP::setHeadersByCode(404);
				break;
		}

		// querystring provided?
		if($this->getParameter('querystring') !== null)
		{
			// split into file and parameters
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
		$this->tpl->assign('message', BL::err(SpoonFilter::toCamelCase(htmlspecialchars($errorType), '-')));
	}
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -64,7 +64,7 @@
 				SpoonHTTP::setHeadersByCode(404);
 
 				// give a nice error, so we can detect which file is missing
-				echo 'Requested file (' . implode('?', $chunks) . ') not found.';
+				echo 'Requested file (' . htmlspecialchars($this->getParameter('querystring')) . ') not found.';
 
 				// stop script execution
 				exit;
```
