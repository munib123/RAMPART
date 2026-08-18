# CrossVul Fix Pair: Improper Access Control in php
**Pair ID:** 5468_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5468_0`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```php
Lines 63-103 of the vulnerable file.

			Request::USER_AGENT_MS_EDGE,
			Request::USER_AGENT_CHROME,
			Request::USER_AGENT_FIREFOX,
			Request::USER_AGENT_SAFARI,
		]);
	}

	/**
	 * @param \Exception $ex
	 */
	public function logException(\Exception $ex) {
		if ($ex instanceof Exception) {
			$httpCode = $ex->getHTTPCode();
			$headers = $ex->getHTTPHeaders($this->server);
		} else {
			$httpCode = 500;
			$headers = [];
		}
		$this->server->httpResponse->addHeaders($headers);
		$this->server->httpResponse->setStatus($httpCode);
		$body = $this->generateBody($ex);
		$this->server->httpResponse->setBody($body);
		$this->sendResponse();
	}

	/**
	 * @codeCoverageIgnore
	 * @param \Exception $ex
	 * @param int $httpCode
	 * @return bool|string
	 */
	public function generateBody(\Exception $exception) {
		$request = \OC::$server->getRequest();
		$content = new OC_Template('dav', 'exception', 'guest');
		$content->assign('title', $this->server->httpResponse->getStatusText());
		$content->assign('message', $exception->getMessage());
		$content->assign('errorClass', get_class($exception));
		$content->assign('errorMsg', $exception->getMessage());
		$content->assign('errorCode', $exception->getCode());
		$content->assign('file', $exception->getFile());
		$content->assign('line', $exception->getLine());
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -80,38 +80,29 @@
 		}
 		$this->server->httpResponse->addHeaders($headers);
 		$this->server->httpResponse->setStatus($httpCode);
-		$body = $this->generateBody($ex);
+		$body = $this->generateBody();
 		$this->server->httpResponse->setBody($body);
 		$this->sendResponse();
 	}
 
 	/**
 	 * @codeCoverageIgnore
-	 * @param \Exception $ex
-	 * @param int $httpCode
 	 * @return bool|string
 	 */
-	public function generateBody(\Exception $exception) {
+	public function generateBody() {
 		$request = \OC::$server->getRequest();
 		$content = new OC_Template('dav', 'exception', 'guest');
 		$content->assign('title', $this->server->httpResponse->getStatusText());
-		$content->assign('message', $exception->getMessage());
-		$content->assign('errorClass', get_class($exception));
-		$content->assign('errorMsg', $exception->getMessage());
-		$content->assign('errorCode', $exception->getCode());
-		$content->assign('file', $exception->getFile());
-		$content->assign('line', $exception->getLine());
-		$content->assign('trace', $exception->getTraceAsString());
-		$content->assign('debugMode', \OC::$server->getSystemConfig()->getValue('debug', false));
 		$content->assign('remoteAddr', $request->getRemoteAddress());
 		$content->assign('requestID', $request->getId());
 		return $content->fetchPage();
 	}
 
-	/*
+	/**
 	 * @codeCoverageIgnore
 	 */
 	public function sendResponse() {
 		$this->server->sapi->sendResponse($this->server->httpResponse);
+		exit();
 	}
 }
```
