# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5455_7
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5455_7`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 245-285 of the vulnerable file.

			]
		);*/
		$this->assertEquals($result, $response);
	}

	public function testGetFilesWithBrokenSetup() {
		$location = '';
		$features = '';
		$etag = 1111222233334444;
		$mediatypes = 'image/png';
		$exceptionMessage = 'Aïe!';
		$this->searchFolderService->expects($this->once())
								  ->method('getCurrentFolder')
								  ->with(
									  $location,
									  [$features]
								  )
								  ->willThrowException(new ServiceException($exceptionMessage));
		// Default status code when something breaks
		$status = Http::STATUS_INTERNAL_SERVER_ERROR;
		$errorMessage = [
			'message' => $exceptionMessage . ' (' . $status . ')',
			'success' => false
		];
		/** @type JSONResponse $response */
		$response = $this->controller->getList($location, $features, $etag, $mediatypes);

		$this->assertEquals($errorMessage, $response->getData());
	}

	public function providesFilesData() {
		$location = 'folder1';
		$folderPathFromRoot = 'user/files/' . $location;

		return [
			[
				['path' => $folderPathFromRoot . '/deep/folder/to/test/path/reduction.png'],
				$folderPathFromRoot . '/deep/reduction.png',
				$folderPathFromRoot
			],
			[
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -262,8 +262,12 @@
 								  ->willThrowException(new ServiceException($exceptionMessage));
 		// Default status code when something breaks
 		$status = Http::STATUS_INTERNAL_SERVER_ERROR;
+		$this->request
+			->expects($this->once())
+			->method('getId')
+			->willReturn('1234');
 		$errorMessage = [
-			'message' => $exceptionMessage . ' (' . $status . ')',
+			'message' => 'An error occurred. Request ID: 1234',
 			'success' => false
 		];
 		/** @type JSONResponse $response */
```
