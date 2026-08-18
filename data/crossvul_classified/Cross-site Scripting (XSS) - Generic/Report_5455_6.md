# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5455_6
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5455_6`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 153-194 of the vulnerable file.

	 */
	public function testCannotGetConfig() {
		$features = $this->mockConfigRetrievalError();
		$slideshow = true;
		$nativeSvgSupport = false;
		$this->mockSupportedMediaTypes($slideshow, $nativeSvgSupport, $this->baseMimeTypes);

		$response = $this->controller->get($slideshow);

		$this->assertEquals(
			['features' => $features, 'mediatypes' => $this->baseMimeTypes], $response
		);
	}

	public function testGetConfigWithBrokenSystem() {
		$slideshow = true;
		$exceptionMessage = 'Aïe!';
		$this->configService->expects($this->any())
							->method('getFeaturesList')
							->willThrowException(new ServiceException($exceptionMessage));
		// Default status code when something breaks
		$status = Http::STATUS_INTERNAL_SERVER_ERROR;
		$errorMessage = [
			'message' => $exceptionMessage  . ' (' . $status . ')',
			'success' => false
		];
		/** @type JSONResponse $response */
		$response = $this->controller->get($slideshow);

		$this->assertEquals($errorMessage, $response->getData());
	}

	/**
	 * Mocks ConfigService->getFeaturesList
	 *
	 * @param $features
	 */
	private function mockFeaturesList($features) {
		$this->configService->expects($this->any())
							->method('getFeaturesList')
							->willReturn($features);
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -170,10 +170,12 @@
 		$this->configService->expects($this->any())
 							->method('getFeaturesList')
 							->willThrowException(new ServiceException($exceptionMessage));
-		// Default status code when something breaks
-		$status = Http::STATUS_INTERNAL_SERVER_ERROR;
+		$this->request
+			->expects($this->once())
+			->method('getId')
+			->willReturn('1234');
 		$errorMessage = [
-			'message' => $exceptionMessage  . ' (' . $status . ')',
+			'message' => 'An error occurred. Request ID: 1234',
 			'success' => false
 		];
 		/** @type JSONResponse $response */
```
