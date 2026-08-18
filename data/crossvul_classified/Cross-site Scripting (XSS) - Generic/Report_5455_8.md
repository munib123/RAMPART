# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5455_8
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5455_8`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 3-43 of the vulnerable file.

 * Gallery
 *
 * This file is licensed under the Affero General Public License version 3 or
 * later. See the COPYING file.
 *
 * @author Olivier Paroz <galleryapps@oparoz.com>
 *
 * @copyright Olivier Paroz 2016
 */

namespace OCA\Gallery\Controller;

use OCP\AppFramework\Http;
use OCP\AppFramework\Http\JSONResponse;
use OCP\AppFramework\Http\RedirectResponse;

use OCA\Gallery\Environment\NotFoundEnvException;
use OCA\Gallery\Service\NotFoundServiceException;
use OCA\Gallery\Service\ForbiddenServiceException;
use OCA\Gallery\Service\InternalServerErrorServiceException;

/**
 * Class HttpErrorTest
 *
 * @package OCA\Gallery\Controller
 */
class HttpErrorTest extends \Test\TestCase {

	/** @var string */
	private $appName = 'gallery';

	/**
	 * @return array
	 */
	public function providesExceptionData() {
		$notFoundEnvMessage = 'Not found in env';
		$notFoundEnvException = new NotFoundEnvException($notFoundEnvMessage);
		$notFoundEnvStatus = Http::STATUS_NOT_FOUND;

		$notFoundServiceMessage = 'Not found in service';
		$notFoundServiceException = new NotFoundServiceException($notFoundServiceMessage);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -20,6 +20,8 @@
 use OCA\Gallery\Service\NotFoundServiceException;
 use OCA\Gallery\Service\ForbiddenServiceException;
 use OCA\Gallery\Service\InternalServerErrorServiceException;
+use OCP\ILogger;
+use OCP\IRequest;
 
 /**
  * Class HttpErrorTest
@@ -35,11 +37,11 @@
 	 * @return array
 	 */
 	public function providesExceptionData() {
-		$notFoundEnvMessage = 'Not found in env';
+		$notFoundEnvMessage = 'An error occurred. Request ID: 1234';
 		$notFoundEnvException = new NotFoundEnvException($notFoundEnvMessage);
 		$notFoundEnvStatus = Http::STATUS_NOT_FOUND;
 
-		$notFoundServiceMessage = 'Not found in service';
+		$notFoundServiceMessage = 'An error occurred. Request ID: 1234';
 		$notFoundServiceException = new NotFoundServiceException($notFoundServiceMessage);
 		$notFoundServiceStatus = Http::STATUS_NOT_FOUND;
 
@@ -47,11 +49,11 @@
 		$forbiddenServiceException = new ForbiddenServiceException($forbiddenServiceMessage);
 		$forbiddenServiceStatus = Http::STATUS_FORBIDDEN;
 
-		$errorServiceMessage = 'Broken service';
+		$errorServiceMessage = 'An error occurred. Request ID: 1234';
 		$errorServiceException = new InternalServerErrorServiceException($errorServiceMessage);
 		$errorServiceStatus = Http::STATUS_INTERNAL_SERVER_ERROR;
 
-		$coreServiceMessage = 'Broken core';
+		$coreServiceMessage = 'An error occurred. Request ID: 1234';
 		$coreServiceException = new \Exception($coreServiceMessage);
 		$coreServiceStatus = Http::STATUS_INTERNAL_SERVER_ERROR;
 
@@ -72,12 +74,32 @@
 	 * @param String $status
 	 */
 	public function testJsonError($exception, $message, $status) {
-		$httpError = $this->getMockForTrait('\OCA\Gallery\Controller\HttpError');
+		$request = $this->createMock(IRequest::class);
+		$logger = $this->createMock(ILogger::class);
+
+		if($exception instanceof ForbiddenServiceException) {
+			$amount = 0;
+			$message = $message . ' (' . $status . ')';
+		} else {
+			$amount = 1;
+		}
+
+		$logger
+			->expects($this->exactly($amount))
+			->method('logException')
+			->with($exception, ['app' => 'gallery']);
+		$request
+			->expects($this->exactly($amount))
+			->method('getId')
+			->willReturn('1234');
+
+		/** @var HttpError $httpError */
+		$httpError = $this->getMockForTrait(HttpError::class);
 		/** @type JSONResponse $response */
-		$response = $httpError->jsonError($exception);
+		$response = $httpError->jsonError($exception, $request, $logger);
 
-		$this->assertEquals(
-			['message' => $message . ' (' . $status . ')', 'success' => false], $response->getData()
+		$this->assertSame(
+			['message' => $message, 'success' => false], $response->getData()
 		);
 		$this->assertEquals($status, $response->getStatus());
 	}
```
