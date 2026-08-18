# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5455_4
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5455_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-39 of the vulnerable file.

<?php
/**
 * Gallery
 *
 * This file is licensed under the Affero General Public License version 3 or
 * later. See the COPYING file.
 *
 * @author Bernhard Posselt <dev@bernhard-posselt.com>
 * @author Olivier Paroz <galleryapps@oparoz.com>
 *
 * @copyright Bernhard Posselt 2014-2015
 * @copyright Olivier Paroz 2014-2016
 */

namespace OCA\Gallery\Controller;

use Exception;

use OCP\IURLGenerator;

use OCP\AppFramework\Http;
use OCP\AppFramework\Http\JSONResponse;
use OCP\AppFramework\Http\RedirectResponse;

use OCA\Gallery\Environment\NotFoundEnvException;
use OCA\Gallery\Service\NotFoundServiceException;
use OCA\Gallery\Service\ForbiddenServiceException;

/**
 * Our classes extend both Controller and ApiController, so we need to use
 * traits to add some common methods
 *
 * @package OCA\Gallery\Controller
 */
trait HttpError {

	/**
	 * @param \Exception $exception
	 *
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -16,6 +16,8 @@
 
 use Exception;
 
+use OCP\ILogger;
+use OCP\IRequest;
 use OCP\IURLGenerator;
 
 use OCP\AppFramework\Http;
@@ -36,17 +38,29 @@
 
 	/**
 	 * @param \Exception $exception
+	 * @param IRequest $request
+	 * @param ILogger $logger
 	 *
 	 * @return JSONResponse
 	 */
-	public function jsonError(Exception $exception) {
-		$message = $exception->getMessage();
+	public function jsonError(Exception $exception,
+							  IRequest $request,
+							  ILogger $logger) {
 		$code = $this->getHttpStatusCode($exception);
+
+		// If the exception is not of type ForbiddenServiceException only show a
+		// generic error message to avoid leaking information.
+		if(!($exception instanceof ForbiddenServiceException)) {
+			$logger->logException($exception, ['app' => 'gallery']);
+			$message = sprintf('An error occurred. Request ID: %s', $request->getId());
+		} else {
+			$message = $exception->getMessage() . ' (' . $code . ')';
+		}
 
 		return new JSONResponse(
 			[
-				'message' => $message . ' (' . $code . ')',
-				'success' => false
+				'message' => $message,
+				'success' => false,
 			],
 			$code
 		);
```
