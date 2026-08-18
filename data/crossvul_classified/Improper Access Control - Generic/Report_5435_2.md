# CrossVul Fix Pair: Improper Access Control in php
**Pair ID:** 5435_2
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5435_2`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```php
Lines 44-84 of the vulnerable file.


		return $client->send($request);
	}

	/**
	 * @Given /^User "([^"]*)" moved file "([^"]*)" to "([^"]*)"$/
	 */
	public function userMovedFile($user, $fileSource, $fileDestination){
		$fullUrl = substr($this->baseUrl, 0, -4) . $this->davPath;
		$headers['Destination'] = $fullUrl . $fileDestination;
		$this->response = $this->makeDavRequest($user, "MOVE", $fileSource, $headers);
		PHPUnit_Framework_Assert::assertEquals(201, $this->response->getStatusCode());
	}

	/**
	 * @When /^User "([^"]*)" moves file "([^"]*)" to "([^"]*)"$/
	 */
	public function userMovesFile($user, $fileSource, $fileDestination){
		$fullUrl = substr($this->baseUrl, 0, -4) . $this->davPath;
		$headers['Destination'] = $fullUrl . $fileDestination;
		$this->response = $this->makeDavRequest($user, "MOVE", $fileSource, $headers);
	}

	/**
	 * @When /^Downloading file "([^"]*)" with range "([^"]*)"$/
	 */
	public function downloadFileWithRange($fileSource, $range){
		$fullUrl = substr($this->baseUrl, 0, -4) . $this->davPath;
		$headers['Range'] = $range;
		$this->response = $this->makeDavRequest($this->currentUser, "GET", $fileSource, $headers);
	}

	/**
	 * @When /^Downloading last public shared file with range "([^"]*)"$/
	 */
	public function downloadPublicFileWithRange($range){
		$token = $this->lastShareData->data->token;
		$fullUrl = substr($this->baseUrl, 0, -4) . "public.php/webdav";
		$headers['Range'] = $range;

		$client = new GClient();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -61,7 +61,27 @@
 	public function userMovesFile($user, $fileSource, $fileDestination){
 		$fullUrl = substr($this->baseUrl, 0, -4) . $this->davPath;
 		$headers['Destination'] = $fullUrl . $fileDestination;
-		$this->response = $this->makeDavRequest($user, "MOVE", $fileSource, $headers);
+		try {
+			$this->response = $this->makeDavRequest($user, "MOVE", $fileSource, $headers);
+		} catch (\GuzzleHttp\Exception\ClientException $e) {
+			$this->response = $e->getResponse();
+		}
+	}
+
+	/**
+	 * @When /^User "([^"]*)" copies file "([^"]*)" to "([^"]*)"$/
+	 * @param string $user
+	 * @param string $fileSource
+	 * @param string $fileDestination
+	 */
+	public function userCopiesFile($user, $fileSource, $fileDestination){
+		$fullUrl = substr($this->baseUrl, 0, -4) . $this->davPath;
+		$headers['Destination'] = $fullUrl . $fileDestination;
+		try {
+			$this->response = $this->makeDavRequest($user, "COPY", $fileSource, $headers);
+		} catch (\GuzzleHttp\Exception\ClientException $e) {
+			$this->response = $e->getResponse();
+		}
 	}
 
 	/**
@@ -110,7 +130,11 @@
 	 * @When Downloading file :fileName
 	 */
 	public function downloadingFile($fileName) {
-		$this->response = $this->makeDavRequest($this->currentUser, 'GET', $fileName, []);
+		try {
+			$this->response = $this->makeDavRequest($this->currentUser, 'GET', $fileName, []);
+		} catch (\GuzzleHttp\Exception\ClientException $e) {
+			$this->response = $e->getResponse();
+		}
 	}
 
 	/**
```
